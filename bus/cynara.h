/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* cynara.h  Cynara runtime privilege checking
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

#include "bus.h"
#include "check.h"

BusCynara *bus_cynara_new             (BusCheck *check, DBusError *error);
BusCynara *bus_cynara_ref             (BusCynara *cynara);
void       bus_cynara_unref           (BusCynara *cynara);
BusResult  bus_cynara_check_privilege (BusCynara *cynara,
                                       DBusMessage *message,
                                       DBusConnection *sender,
                                       DBusConnection *addressed_recipient,
                                       DBusConnection *proposed_recipient,
                                       const char *privilege,
                                       BusDeferredMessageStatus check_type,
                                       BusDeferredMessage **deferred_message);
