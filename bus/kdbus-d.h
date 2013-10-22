/*
 * kdbus-d.h
 *
 *  Created on: Sep 4, 2013
 *      Author: r.pajak
 *
 *  kdbus add-on to dbus daemon
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
DBusConnection* daemon_as_client(DBusBusType type, char* address, DBusError *error);
dbus_bool_t register_daemon_name(DBusConnection* connection);
dbus_bool_t kdbus_register_policy (const DBusString *service_name, DBusConnection* connection);
dbus_uint32_t kdbus_request_name(DBusConnection* connection, const DBusString *service_name, dbus_uint32_t flags, __u64 sender_id);
dbus_uint32_t kdbus_release_name(DBusConnection* connection, const DBusString *service_name, __u64 sender_id);
dbus_bool_t kdbus_list_services (DBusConnection* connection, char ***listp, int *array_len);
dbus_bool_t kdbus_add_match_rule (DBusConnection* connection, DBusMessage* message, const char* text, DBusError* error);
dbus_bool_t kdbus_remove_match (DBusConnection* connection, DBusMessage* message, DBusError* error);
dbus_bool_t kdbus_get_connection_unix_user(DBusConnection* connection, DBusMessage* message, unsigned long* uid, DBusError* error);
dbus_bool_t kdbus_get_connection_unix_process_id(DBusConnection* connection, DBusMessage* message, unsigned long* pid, DBusError* error);
dbus_bool_t kdbus_get_connection_unix_selinux_security_context(DBusConnection* connection, DBusMessage* message, DBusMessage* reply, DBusError* error);

DBusConnection* create_phantom_connection(DBusConnection* connection, const char* unique_name, DBusError* error);
dbus_bool_t register_kdbus_starters(DBusConnection* connection);
dbus_bool_t update_kdbus_starters(DBusConnection* connection);
void handleNameOwnerChanged(DBusMessage *msg, BusTransaction *transaction, DBusConnection *connection);
#endif /* KDBUS_H_ */
