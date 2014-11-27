/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* check.h  Bus security policy runtime check
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

#ifndef BUS_CHECK_H
#define BUS_CHECK_H

#include "bus.h"
#include "policy.h"


typedef void (*BusCheckResponseFunc) (BusDeferredMessage *message,
                                      BusResult result);

typedef enum {
  BUS_DEFERRED_MESSAGE_CHECK_SEND      = 1 << 0,
  BUS_DEFERRED_MESSAGE_CHECK_RECEIVE   = 1 << 1,
  BUS_DEFERRED_MESSAGE_CHECK_OWN       = 1 << 2,
} BusDeferredMessageStatus;


BusCheck   *bus_check_new         (BusContext *context,
                                   DBusError *error);
BusCheck   *bus_check_ref         (BusCheck *check);
void        bus_check_unref       (BusCheck *check);

BusContext *bus_check_get_context (BusCheck *check);
BusCynara  *bus_check_get_cynara  (BusCheck *check);
BusResult   bus_check_privilege   (BusCheck *check,
                                   DBusMessage *message,
                                   DBusConnection *sender,
                                   DBusConnection *addressed_recipient,
                                   DBusConnection *proposed_recipient,
                                   const char *privilege,
                                   BusDeferredMessageStatus check_type,
                                   BusDeferredMessage **deferred_message);

BusDeferredMessage *bus_deferred_message_new                (DBusMessage *message,
                                                             DBusConnection *sender,
                                                             DBusConnection *addressed_recipient,
                                                             DBusConnection *proposed_recipient,
                                                             BusResult response);

BusDeferredMessage *bus_deferred_message_ref                (BusDeferredMessage *deferred_message);
void                bus_deferred_message_unref              (BusDeferredMessage *deferred_message);
void                bus_deferred_message_response_received  (BusDeferredMessage *deferred_message,
                                                             BusResult result);
#endif /* BUS_CHECK_H */
