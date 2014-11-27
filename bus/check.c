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

BusContext *
bus_check_get_context (BusCheck *check)
{
  return check->context;
}

BusCynara *
bus_check_get_cynara (BusCheck *check)
{
  return check->cynara;
}

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

void
bus_deferred_message_response_received (BusDeferredMessage *deferred_message,
                                        BusResult result)
{
  if (deferred_message->response_callback != NULL)
    {
      deferred_message->response_callback(deferred_message, result);
    }
}
