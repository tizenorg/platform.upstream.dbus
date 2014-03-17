/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-policy.h - helper library for fine-grained userspace policy handling
 *
 * Copyright (C) 2014 Samsung Electronics
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
 * Author: Lukasz Skalski <l.skalski@samsung.com>
 *
 */

#ifndef DBUS_POLICY_H
#define DBUS_POLICY_H

#define SYSTEM_BUS_CONF_FILE  "/etc/dbus-1/system.conf"
#define SESSION_BUS_CONF_FILE "/etc/dbus-1/session.conf"

#define SYSTEM_BUS   1
#define SESSION_BUS  2

#define NO_REQUESTED_REPLY  0
#define REQUESTED_REPLY     1

void *dbus_policy_init (unsigned int bus_type);
void  dbus_policy_free (void *client_policy);

int dbus_policy_check_can_send (void        *client_policy,
                                int          message_type,
                                const char  *destination,
                                const char  *path,
                                const char  *interface,
                                const char  *member,
                                const char  *error_name,
                                int          reply_serial,
                                int          requested_reply);

int dbus_policy_check_can_recv (void        *client_policy,
                                int          message_type,
                                const char  *sender,
                                const char  *path,
                                const char  *interface,
                                const char  *member,
                                const char  *error_name,
                                int          reply_serial,
                                int          requested_reply);

int dbus_policy_check_can_own  (void        *client_policy,
                                const char  *service_name);

void dbus_policy_print_rules   (void        *client);

#endif /* DBUS_POLICY_H */
