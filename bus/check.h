/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* check.h  Bus security policy
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

#ifndef BUS_CHECK_H
#define BUS_CHECK_H

#include "policy.h"

BusResult bus_check_privilege (DBusConnection *connection,
                               const char *privilege);

#ifdef DBUS_ENABLE_EMBEDDED_TESTS
extern dbus_bool_t (*bus_check_test_override) (DBusConnection *connection,
                                               const char *privilege);
#endif

#endif /* BUS_CHECK_H */
