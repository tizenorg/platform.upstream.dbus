/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-d.h  kdbus related daemon functions
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

#ifndef KDBUS_D_H_
#define KDBUS_D_H_


#include <dbus/dbus-bus.h>
#include "bus.h"
#include <dbus/dbus-server.h>
#include <linux/types.h>
#include <dbus/dbus-transport-kdbus.h>

__u64 sender_name_to_id(const char* name, DBusError* error);
char* make_kdbus_bus(DBusBusType type, DBusError *error);
DBusServer* empty_server_init(char* address);

dbus_bool_t kdbus_register_policy (const DBusString *service_name, DBusConnection* connection);
dbus_uint32_t kdbus_request_name(DBusConnection* connection, const DBusString *service_name, dbus_uint32_t flags, __u64 sender_id);
dbus_uint32_t kdbus_release_name(DBusConnection* connection, const DBusString *service_name, __u64 sender_id);
dbus_bool_t kdbus_list_services (DBusConnection* connection, char ***listp, int *array_len);
dbus_bool_t kdbus_add_match_rule (DBusConnection* connection, DBusMessage* message, const char* text, DBusError* error);
dbus_bool_t kdbus_remove_match (DBusConnection* connection, DBusMessage* message, DBusError* error);

dbus_bool_t add_match_kdbus (DBusTransport* transport, __u64 id, const char *rule);
dbus_bool_t remove_match_kdbus (DBusTransport* transport, __u64 id);

struct nameInfo
{
  __u64 uniqueId;
  __u64 userId;
  __u64 processId;
  __u32 sec_label_len;
  char *sec_label;
};
int kdbus_NameQuery(const char* name, DBusTransport* transport, struct nameInfo* pInfo);

int kdbus_get_name_owner(DBusConnection* connection, const char* name, char* owner);
dbus_bool_t kdbus_get_unix_user(DBusConnection* connection, const char* name, unsigned long* uid, DBusError* error);
dbus_bool_t kdbus_get_connection_unix_process_id(DBusConnection* connection, const char* name, unsigned long* pid, DBusError* error);
dbus_bool_t kdbus_get_connection_unix_selinux_security_context(DBusConnection* connection, DBusMessage* message, DBusMessage* reply, DBusError* error);

dbus_bool_t dbus_connection_get_unix_user (DBusConnection *connection, unsigned long  *uid);
dbus_bool_t dbus_connection_get_unix_process_id (DBusConnection *connection, unsigned long  *pid);

DBusConnection* daemon_as_client(DBusBusType type, char* address, DBusError *error);
dbus_bool_t register_daemon_name(DBusConnection* connection);
DBusConnection* create_phantom_connection(DBusConnection* connection, const char* unique_name, DBusError* error);
dbus_bool_t register_kdbus_starters(DBusConnection* connection);
dbus_bool_t update_kdbus_starters(DBusConnection* connection);

void handleNameOwnerChanged(DBusMessage *msg, BusTransaction *transaction, DBusConnection *connection);
#endif /* KDBUS_H_ */
