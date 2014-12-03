/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* check.c  Bus security policy runtime check
 *
 * Copyright (C) 2014  Intel, Inc.
 * Copyright (c) 2014  Samsung Electronics, Ltd.
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>
#include "check.h"
#include "connection.h"
#include "dispatch.h"
#include "cynara.h"
#include "utils.h"
#include <dbus/dbus-connection-internal.h>
#include <dbus/dbus-message-internal.h>
#include <dbus/dbus-internals.h>


typedef struct BusCheck
{
  int refcount;

  BusContext *context;
  BusCynara *cynara;
} BusCheck;

typedef struct BusDeferredMessage
{
  int refcount;

  DBusMessage *message;
  DBusConnection *sender;
  DBusConnection *proposed_recipient;
  DBusConnection *addressed_recipient;
  dbus_bool_t full_dispatch;
  BusDeferredMessageStatus status;
  BusResult response;
  BusCheckResponseFunc response_callback;
} BusDeferredMessage;

BusCheck *
bus_check_new (BusContext *context, DBusError *error)
{
  BusCheck *check;

  check = dbus_new(BusCheck, 1);
  if (check == NULL)
    {
      BUS_SET_OOM(error);
      return NULL;
    }

  check->refcount = 1;
  check->context = context;
  check->cynara = bus_cynara_new(check, error);
  if (dbus_error_is_set(error))
    {
      dbus_free(check);
      return NULL;
    }

  return check;
}

BusCheck *
bus_check_ref (BusCheck *check)
{
  _dbus_assert (check->refcount > 0);
  check->refcount += 1;

  return check;
}

void
bus_check_unref (BusCheck *check)
{
  _dbus_assert (check->refcount > 0);

  check->refcount -= 1;

  if (check->refcount == 0)
    {
      bus_cynara_unref(check->cynara);
      dbus_free(check);
    }
}

BusContext*
bus_check_get_context (BusCheck *check)
{
  return check->context;
}

BusCynara*
bus_check_get_cynara (BusCheck *check)
{
  return check->cynara;
}

static void
bus_check_enable_dispatch_callback (BusDeferredMessage *message,
                                    BusResult result)
{
  _dbus_verbose("bus_check_enable_dispatch_callback called message=%p\n", message);
  _dbus_connection_enable_dispatch(message->sender);
}

static void
bus_check_queued_message_reply_callback(BusDeferredMessage *message,
                                        BusResult result)
{
  _dbus_verbose("bus_check_queued_message_reply_callback called message=%p\n", message);
  /*
   * If send rule allows us to send message we still need to check receive rules.
   * Set result to BUS_RESULT_LATER which will trigger policy check.
   */
  if ((message->status & BUS_DEFERRED_MESSAGE_CHECK_SEND)
      && result == BUS_RESULT_TRUE)
    result = BUS_RESULT_LATER;

  message->response = result;
  message->status = 0; /* mark message as not waiting for response */

  if (bus_connection_is_active(message->proposed_recipient))
    bus_connection_dispatch_deferred (message->proposed_recipient);
}


dbus_bool_t
bus_deferred_message_queue_at_recipient (BusDeferredMessage *deferred_message,
                                         dbus_bool_t full_dispatch,
                                         dbus_bool_t prepend)
{
  _dbus_assert(deferred_message != NULL);
  _dbus_assert(deferred_message->proposed_recipient != NULL);

  if (bus_connection_queue_deferred_message(deferred_message->proposed_recipient,
         deferred_message, prepend))
    {
      deferred_message->response_callback = bus_check_queued_message_reply_callback;
      deferred_message->full_dispatch = full_dispatch;
      return TRUE;
    }

  return FALSE;
}

void
bus_deferred_message_disable_sender (BusDeferredMessage *deferred_message)
{
  _dbus_assert(deferred_message != NULL);
  _dbus_assert(deferred_message->sender != NULL);

  _dbus_connection_disable_dispatch(deferred_message->sender);
  deferred_message->response_callback = bus_check_enable_dispatch_callback;
}

#ifdef DBUS_ENABLE_EMBEDDED_TESTS
dbus_bool_t (*bus_check_test_override) (DBusConnection *connection,
                                        const char *privilege);
#endif

BusResult
bus_check_privilege (BusCheck *check,
                     DBusMessage *message,
                     DBusConnection *sender,
                     DBusConnection *addressed_recipient,
                     DBusConnection *proposed_recipient,
                     const char *privilege,
                     BusDeferredMessageStatus check_type,
                     BusDeferredMessage **deferred_message)
{
  BusResult result = BUS_RESULT_FALSE;
  BusCynara *cynara;
  DBusConnection *connection;

  connection = check_type == BUS_DEFERRED_MESSAGE_CHECK_RECEIVE ? proposed_recipient : sender;

  if (!dbus_connection_get_is_connected(connection))
    {
      return BUS_RESULT_FALSE;
    }

#ifdef DBUS_ENABLE_EMBEDDED_TESTS
  if (bus_check_test_override)
    return bus_check_test_override (connection, privilege);
#endif

  /* ask policy checkers */
#ifdef DBUS_ENABLE_CYNARA
  cynara = bus_check_get_cynara(check);
  result = bus_cynara_check_privilege(cynara, message, sender, addressed_recipient,
      proposed_recipient, privilege, check_type, deferred_message);
#endif

  if (result == BUS_RESULT_LATER && deferred_message != NULL)
    {
      (*deferred_message)->status |= check_type;
    }
  return result;
}

BusDeferredMessage *bus_deferred_message_new (DBusMessage *message,
                                              DBusConnection *sender,
                                              DBusConnection *addressed_recipient,
                                              DBusConnection *proposed_recipient,
                                              BusResult response)
{
  BusDeferredMessage *deferred_message;

  deferred_message = dbus_new(BusDeferredMessage, 1);
  if (deferred_message == NULL)
    {
      return NULL;
    }

  deferred_message->refcount = 1;
  deferred_message->sender = sender != NULL ? dbus_connection_ref(sender) : NULL;
  deferred_message->addressed_recipient = addressed_recipient != NULL ? dbus_connection_ref(addressed_recipient) : NULL;
  deferred_message->proposed_recipient = proposed_recipient != NULL ? dbus_connection_ref(proposed_recipient) : NULL;
  deferred_message->message = dbus_message_ref(message);
  deferred_message->response = response;
  deferred_message->status = 0;
  deferred_message->full_dispatch = FALSE;
  deferred_message->response_callback = NULL;

  return deferred_message;
}

BusDeferredMessage *
bus_deferred_message_ref (BusDeferredMessage *deferred_message)
{
  _dbus_assert (deferred_message->refcount > 0);
  deferred_message->refcount += 1;
  return deferred_message;
}

void
bus_deferred_message_unref (BusDeferredMessage *deferred_message)
{
  _dbus_assert (deferred_message->refcount > 0);

  deferred_message->refcount -= 1;

   if (deferred_message->refcount == 0)
     {
       dbus_message_unref(deferred_message->message);
       if (deferred_message->sender != NULL)
           dbus_connection_unref(deferred_message->sender);
       if (deferred_message->addressed_recipient != NULL)
           dbus_connection_unref(deferred_message->addressed_recipient);
       if (deferred_message->proposed_recipient != NULL)
           dbus_connection_unref(deferred_message->proposed_recipient);
       dbus_free(deferred_message);
     }
}

BusResult
bus_deferred_message_dispatch (BusDeferredMessage *deferred_message)
{
  BusContext *context = bus_connection_get_context (deferred_message->proposed_recipient);
  BusTransaction *transaction = bus_transaction_new (context);
  BusResult result = BUS_RESULT_TRUE;
  DBusError error;

  if (transaction == NULL)
    {
      return BUS_RESULT_FALSE;
    }

  if (!deferred_message->full_dispatch)
    {
      if (deferred_message->response == BUS_RESULT_LATER)
        {
          BusDeferredMessage *deferred_message2;
          result = bus_context_check_security_policy (context, transaction,
                                                      deferred_message->sender,
                                                      deferred_message->addressed_recipient,
                                                      deferred_message->proposed_recipient,
                                                      deferred_message->message, NULL,
                                                      &deferred_message2);

          if (result == BUS_RESULT_LATER)
            {
              /* prepend at recipient */
              if (!bus_deferred_message_queue_at_recipient(deferred_message2, FALSE, TRUE))
                  result = BUS_RESULT_FALSE;
            }
        }
      else
        result = deferred_message->response;

      /* silently drop messages on access denial */
      if (result == BUS_RESULT_TRUE)
        {
          if (!bus_transaction_send (transaction, deferred_message->proposed_recipient, deferred_message->message, TRUE))
            result = BUS_RESULT_FALSE;
        }

      if (result != BUS_RESULT_LATER)
        bus_transaction_execute_and_free(transaction);
      else
        bus_transaction_cancel_and_free(transaction);

      return result;
    }

  /* do not attempt to send message if sender has disconnected */
  if (deferred_message->sender != NULL && !bus_connection_is_active(deferred_message->sender))
    {
      bus_transaction_cancel_and_free(transaction);
      return BUS_RESULT_FALSE;
    }

  dbus_error_init(&error);
  result = bus_dispatch_matches(transaction, deferred_message->sender,
      deferred_message->addressed_recipient, deferred_message->message, TRUE, &error);

  if (result == BUS_RESULT_LATER)
    {
      /* Message deferring was already done in bus_dispatch_matches */
      bus_transaction_cancel_and_free(transaction);
      return result;
    }

  /* this part is a copy & paste from bus_dispatch function. Probably can be moved to a function */
  if (dbus_error_is_set (&error))
    {
      if (!dbus_connection_get_is_connected (deferred_message->sender))
        {
          /* If we disconnected it, we won't bother to send it any error
           * messages.
           */
          _dbus_verbose ("Not sending error to connection we disconnected\n");
        }
      else if (dbus_error_has_name (&error, DBUS_ERROR_NO_MEMORY))
        {
          bus_connection_send_oom_error (deferred_message->sender, deferred_message->message);

          /* cancel transaction due to OOM */
          if (transaction != NULL)
            {
              bus_transaction_cancel_and_free (transaction);
              transaction = NULL;
            }
        }
      else
        {
          /* Try to send the real error, if no mem to do that, send
           * the OOM error
           */
          _dbus_assert (transaction != NULL);
          if (!bus_transaction_send_error_reply (transaction, deferred_message->sender,
                                                 &error, deferred_message->message))
            {
              bus_connection_send_oom_error (deferred_message->sender, deferred_message->message);

              /* cancel transaction due to OOM */
              if (transaction != NULL)
                {
                  bus_transaction_cancel_and_free (transaction);
                  transaction = NULL;
                }
            }
        }
    }

  if (transaction != NULL)
    {
      bus_transaction_execute_and_free (transaction);
    }

  dbus_error_free(&error);

  return result;
}

dbus_bool_t
bus_deferred_message_waits_for_check(BusDeferredMessage *deferred_message)
{
  return deferred_message->status != 0;
}

DBusConnection *
bus_deferred_message_get_recipient(BusDeferredMessage *deferred_message)
{
  return deferred_message->proposed_recipient;
}

BusDeferredMessageStatus
bus_deferred_message_get_status (BusDeferredMessage *deferred_message)
{
  return deferred_message->status;
}

void
bus_deferred_message_response_received (BusDeferredMessage *deferred_message,
                                        BusResult result)
{
  if (deferred_message->response_callback != NULL)
    {
      deferred_message->response_callback(deferred_message, result);
    }
}

void
bus_deferred_message_cancel_transaction_hook (void *data)
{
  BusDeferredMessage *deferred_message = (BusDeferredMessage *)data;
  bus_connection_remove_deferred_message(deferred_message->proposed_recipient, deferred_message);
}