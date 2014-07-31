/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* check.c  Bus security policy runtime check
 *
 * Copyright (C) 2014  Intel, Inc.
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
#include "connection.h"
#include "check.h"

#ifdef DBUS_ENABLE_EMBEDDED_TESTS
dbus_bool_t (*bus_check_test_override) (DBusConnection *connection,
                                        const char *privilege);
#endif

BusResult
bus_check_privilege (DBusConnection *connection,
                     const char *privilege)
{
#ifdef DBUS_ENABLE_EMBEDDED_TESTS
  if (bus_check_test_override)
    return bus_check_test_override (connection, privilege);

#endif
  /* TODO: actual implementation... */
  /* Here's roughly how that could work:
   * - check if the result is in the cache
   * - if allowed/denied, return that
   * - if communication with the Cynara daemon is necessary,
   *   then trigger that
   * - return BUS_RESULT_LATER
   *
   * Wait for results either this way:
   * - take a reference to the connection, add it to a list of
   *   connections waiting for a Cynara response
   * - _dbus_connection_disable_dispatch (connection)
   * - when any response from Cynara comes in,
   *   _dbus_connection_enable_dispatch (connection)
   *   for *all* blocked connections
   * or (more efficiently):
   * - attach the connection pointer to the asynchronous
   *   Cynara call and enable only that
   *
   * Optional: If a connection waiting for a Cynara response gets
   * disconnected, then cancel all pending Cynara requests (the
   * request may have triggered a UI dialog which becomes obsolete
   * once the client triggering it goes away).
   *
   * Mandatory (?): check whether the connection is disconnected
   * and if it is, decline access. May be necessary to free the
   * connection of disconnected clients (TODO: check this), unless
   * the pending messages get discarded.
   */
  return BUS_RESULT_FALSE;
}
