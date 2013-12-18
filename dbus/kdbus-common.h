/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-common.h  kdbus related utils for daemon and libdbus
 *
 * Copyright (C) 2013  Samsung Electronics
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version and under the terms of the GNU
 * Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
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

#ifndef KDBUS_COMMON_H_
#define KDBUS_COMMON_H_

#include <dbus/dbus-types.h>
#include <dbus/dbus-transport.h>
#include <dbus/kdbus.h>

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_PART_NEXT(part) \
	(typeof(part))(((uint8_t *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE  0x00800000              /* maximum size of message header and items */
#define KDBUS_ITEM_HEADER_SIZE          offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)

//todo restore if DBus policy will be applied in kdbus somehow
//#define POLICY_TO_KDBUS

dbus_bool_t register_kdbus_policy(const char* name, DBusTransport *transport, unsigned long int uid);
int request_kdbus_name(int fd, const char *name, const __u64 flags, __u64 id);
int release_kdbus_name(int fd, const char *name, __u64 id);

#endif /* KDBUS_COMMON_H_ */
