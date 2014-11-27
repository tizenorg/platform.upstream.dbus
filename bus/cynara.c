/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* cynara.c  Cynara runtime privilege checking
 *
 * Copyright (c) 2014 Samsung Electronics, Ltd.
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
#include "cynara.h"
#include "check.h"
#include "utils.h"

#include <stdio.h>

#include <dbus/dbus.h>
#include <dbus/dbus-watch.h>
#include <dbus/dbus-connection-internal.h>
#include <bus/connection.h>
#ifdef DBUS_ENABLE_CYNARA
#include <cynara-client-async.h>
#endif


#ifdef DBUS_ENABLE_CYNARA
typedef struct BusCynara
{
  int refcount;

  BusContext   *context;
  BusCheck     *check;
  cynara_async *cynara;
  DBusWatch    *cynara_watch;
} BusCynara;

#define USE_CYNARA_CACHE 1
#ifdef USE_CYNARA_CACHE
#define CYNARA_CACHE_SIZE 1000
#endif

static dbus_bool_t bus_cynara_watch_callback(DBusWatch *watch,
                                             unsigned int flags,
                                             void *data);

static void status_callback(int old_fd,
                            int new_fd,
                            cynara_async_status status,
                            void *user_status_data);
static void bus_cynara_check_response_callback (cynara_check_id check_id,
                                                cynara_async_call_cause cause,
                                                int response,
                                                void *user_response_data);
#endif


BusCynara *
bus_cynara_new(BusCheck *check, DBusError *error)
{
#ifdef DBUS_ENABLE_CYNARA
  BusContext *context;
  BusCynara *cynara;
  cynara_async_configuration *conf = NULL;
  int ret;

  cynara = dbus_new(BusCynara, 1);
  if (cynara == NULL)
    {
      BUS_SET_OOM(error);
      return NULL;
    }

  context = bus_check_get_context(check);

  cynara->refcount = 1;
  cynara->check = check;
  cynara->context = context;
  cynara->cynara_watch = NULL;

  ret = cynara_async_configuration_create(&conf);
  if (ret != CYNARA_API_SUCCESS)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED, "Failed to create Cynara configuration");
      goto out;
    }

#ifdef CYNARA_CACHE_SIZE
  ret = cynara_async_configuration_set_cache_size(conf, CYNARA_CACHE_SIZE);
  if (ret != CYNARA_API_SUCCESS)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED, "Failed to Cynara cache size");
      goto out;
    }
#endif

  ret = cynara_async_initialize(&cynara->cynara, conf, &status_callback, cynara);
  if (ret != CYNARA_API_SUCCESS)
    {
      dbus_set_error (error, DBUS_ERROR_FAILED, "Failed to initialize Cynara client");
      goto out;
    }

out:
  cynara_async_configuration_destroy(conf);
  if (ret != CYNARA_API_SUCCESS)
    {
      dbus_free(cynara);
      return NULL;
    }

  return cynara;
#else
  return NULL;
#endif
}

BusCynara *
bus_cynara_ref (BusCynara *cynara)
{
#ifdef DBUS_ENABLE_CYNARA
  _dbus_assert (cynara->refcount > 0);
  cynara->refcount += 1;

  return cynara;
#else
  return NULL;
#endif
}

void
bus_cynara_unref (BusCynara *cynara)
{
#ifdef DBUS_ENABLE_CYNARA
  _dbus_assert (cynara->refcount > 0);

  cynara->refcount -= 1;

  if (cynara->refcount == 0)
    {
      cynara_async_finish(cynara->cynara);
      dbus_free(cynara);
    }
#endif
}

BusResult
bus_cynara_check_privilege (BusCynara *cynara,
                            DBusMessage *message,
                            DBusConnection *sender,
                            DBusConnection *addressed_recipient,
                            DBusConnection *proposed_recipient,
                            const char *privilege,
                            BusDeferredMessageStatus check_type,
                            BusDeferredMessage **deferred_message_param)
{
#ifdef DBUS_ENABLE_CYNARA
  int result;
  unsigned long uid;
  char *label;
  const char *session_id;
  char user[32];
  cynara_check_id check_id;
  DBusConnection *connection = check_type == BUS_DEFERRED_MESSAGE_CHECK_RECEIVE ? proposed_recipient : sender;
  BusDeferredMessage *deferred_message;
  BusResult ret;

  _dbus_assert(connection != NULL);

  if (dbus_connection_get_unix_user(connection, &uid) == FALSE)
      return BUS_RESULT_FALSE;

  if (_dbus_connection_get_linux_security_label(connection, &label) == FALSE || label == NULL)
    {
      _dbus_warn("Failed to obtain security label for connection\n");
      return BUS_RESULT_FALSE;
    }

  session_id = bus_connection_get_cynara_session_id (connection);
  if (session_id == NULL)
    {
      ret = BUS_RESULT_FALSE;
      goto out;
    }

  snprintf(user, sizeof(user), "%lu", uid);

#if USE_CYNARA_CACHE
  result = cynara_async_check_cache(cynara->cynara, label, session_id, user, privilege);
#else
  result = CYNARA_API_CACHE_MISS;
#endif

  switch (result)
  {
  case CYNARA_API_ACCESS_ALLOWED:
    _dbus_verbose("Cynara: got ALLOWED answer from cache (client=%s session_id=%s user=%s privilege=%s)\n",
               label, session_id, user, privilege);
    ret = BUS_RESULT_TRUE;
    break;

  case CYNARA_API_ACCESS_DENIED:
    _dbus_verbose("Cynara: got DENIED answer from cache (client=%s session_id=%s user=%s privilege=%s)\n",
               label, session_id, user, privilege);
    ret = BUS_RESULT_FALSE;
    break;

  case CYNARA_API_CACHE_MISS:
     deferred_message = bus_deferred_message_new(message, sender, addressed_recipient,
         proposed_recipient, BUS_RESULT_LATER);
     if (deferred_message == NULL)
       {
         _dbus_verbose("Failed to allocate memory for deferred message\n");
         ret = BUS_RESULT_FALSE;
         goto out;
       }

    /* callback is supposed to unref deferred_message*/
    result = cynara_async_create_request(cynara->cynara, label, session_id, user, privilege, &check_id,
        &bus_cynara_check_response_callback, deferred_message);
    if (result == CYNARA_API_SUCCESS)
      {
        _dbus_verbose("Created Cynara request: client=%s session_id=%s user=%s privilege=%s check_id=%u "
            "deferred_message=%p\n", label, session_id, user, privilege, (unsigned int)check_id, deferred_message);
        if (deferred_message_param != NULL)
          *deferred_message_param = deferred_message;
        ret = BUS_RESULT_LATER;
      }
    else
      {
        _dbus_verbose("Error on cynara request create: %i\n", result);
        bus_deferred_message_unref(deferred_message);
        ret = BUS_RESULT_FALSE;
      }
    break;
  default:
    _dbus_verbose("Error when accessing Cynara cache: %i\n", result);
    ret = BUS_RESULT_FALSE;
  }
out:
  dbus_free(label);
  return ret;

#else
  return BUS_RESULT_FALSE;
#endif
}



#ifdef DBUS_ENABLE_CYNARA
static void
status_callback(int old_fd, int new_fd, cynara_async_status status,
                void *user_status_data)
{
  BusCynara *cynara = (BusCynara *)user_status_data;
  DBusLoop *loop = bus_context_get_loop(cynara->context);

  if (cynara->cynara_watch != NULL)
    {
      _dbus_loop_remove_watch(loop, cynara->cynara_watch);
      _dbus_watch_invalidate(cynara->cynara_watch);
      _dbus_watch_unref(cynara->cynara_watch);
      cynara->cynara_watch = NULL;
    }

  if (new_fd != -1)
    {
      unsigned int flags;
      DBusWatch *watch;

      switch (status)
      {
      case CYNARA_STATUS_FOR_READ:
        flags = DBUS_WATCH_READABLE;
        break;
      case CYNARA_STATUS_FOR_RW:
        flags = DBUS_WATCH_READABLE | DBUS_WATCH_WRITABLE;
        break;
      default:
        /* Cynara passed unknown status - warn and add RW watch */
        _dbus_verbose("Cynara passed unknown status value: 0x%08X\n", (unsigned int)status);
        flags = DBUS_WATCH_READABLE | DBUS_WATCH_WRITABLE;
        break;
      }

      watch = _dbus_watch_new(new_fd, flags, TRUE, &bus_cynara_watch_callback, cynara, NULL);
      if (watch != NULL)
        {
          if (_dbus_loop_add_watch(loop, watch) == TRUE)
            {
              cynara->cynara_watch = watch;
              return;
            }

          _dbus_watch_invalidate(watch);
          _dbus_watch_unref(watch);
        }

      /* It seems like not much can be done at this point. Cynara events won't be processed
       * until next Cynara function call triggering status callback */
      _dbus_verbose("Failed to add dbus watch\n");
    }
}

static dbus_bool_t
bus_cynara_watch_callback(DBusWatch    *watch,
                          unsigned int  flags,
                          void         *data)
{
  BusCynara *cynara = (BusCynara *)data;
  int result = cynara_async_process(cynara->cynara);
  if (result != CYNARA_API_SUCCESS)
      _dbus_verbose("cynara_async_process returned %d\n", result);

  return result != CYNARA_API_OUT_OF_MEMORY ? TRUE : FALSE;
}

static inline const char *
call_cause_to_string(cynara_async_call_cause cause)
{
  switch (cause)
  {
  case CYNARA_CALL_CAUSE_ANSWER:
    return "ANSWER";
  case CYNARA_CALL_CAUSE_CANCEL:
    return "CANCEL";
  case CYNARA_CALL_CAUSE_FINISH:
    return "FINSIH";
  case CYNARA_CALL_CAUSE_SERVICE_NOT_AVAILABLE:
    return "SERVICE NOT AVAILABLE";
  default:
    return "INVALID";
  }
}

static void
bus_cynara_check_response_callback (cynara_check_id check_id,
                                    cynara_async_call_cause cause,
                                    int response,
                                    void *user_response_data)
{
  BusDeferredMessage *deferred_message = user_response_data;
  BusResult result;

  _dbus_verbose("Cynara callback: check_id=%u, cause=%s response=%i response_data=%p\n",
      (unsigned int)check_id, call_cause_to_string(cause), response, user_response_data);

  if (deferred_message == NULL)
    return;

  if (cause == CYNARA_CALL_CAUSE_ANSWER && response == CYNARA_API_ACCESS_ALLOWED)
    result = BUS_RESULT_TRUE;
  else
    result = BUS_RESULT_FALSE;

  bus_deferred_message_response_received(deferred_message, result);
  bus_deferred_message_unref(deferred_message);
}

#endif /* DBUS_ENABLE_CYNARA */
