/*
 * kdbus-d.c
 *
 *  Created on: Sep 4, 2013
 *      Author: r.pajak
 *
 *  kdbus add-on to dbus daemon
 *
 */

#include "kdbus-d.h"
#include <dbus/kdbus.h>
#include <dbus/dbus-connection-internal.h>
#include <dbus/dbus-bus.h>
#include "dispatch.h"
#include <dbus/kdbus-common.h>
#include <dbus/dbus-transport.h>
#include <dbus/dbus-transport-kdbus.h>

#include <utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

//todo there should be no include below - needed functions should be moved to kdbus-common
#include <dbus/dbus-transport-kdbus.h>

__u64 sender_name_to_id(const char* name, DBusError* error)
{
	__u64 sender_id = 0;

	if(!strncmp(name, ":1.", 3)) /*if name is unique name it must be converted to unique id*/
		sender_id = strtoull(&name[3], NULL, 10);
	else
		dbus_set_error (error, DBUS_ERROR_INVALID_ARGS, "Could not convert sender of the message into kdbus unique id");

	return sender_id;
}

char* make_kdbus_bus(DBusBusType type, DBusError *error)
{
    struct {
        struct kdbus_cmd_bus_make head;
        uint64_t n_size;
        uint64_t n_type;
        char name[64];
    } __attribute__ ((__aligned__(8))) bus_make;

    int fdc, ret;
    char *bus;

    /*TODO Distinguish session and system bus make*/
    /*TODO Add dbus_set_error(error, DBUS_ERROR_FAILED,  "...") (?)*/

    _dbus_verbose("Opening /dev/kdbus/control\n");
    fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
    if (fdc < 0)
    {
        _dbus_verbose("--- error %d (%m)\n", fdc);
        return NULL;
    }

    memset(&bus_make, 0, sizeof(bus_make));
    bus_make.head.bloom_size = 64;
    bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;

    snprintf(bus_make.name, sizeof(bus_make.name), "%u-kdbus", getuid());
    bus_make.n_type = KDBUS_MAKE_NAME;
    bus_make.n_size = KDBUS_PART_HEADER_SIZE + strlen(bus_make.name) + 1;
    bus_make.head.size = sizeof(struct kdbus_cmd_bus_make) + bus_make.n_size;

    _dbus_verbose("Creating bus '%s'\n", bus_make.name);
    ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &bus_make);
    if (ret)
    {
        _dbus_verbose("--- error %d (%m)\n", ret);
        return NULL;
    }

    if (asprintf(&bus, "kdbus:path=/dev/kdbus/%s/bus", bus_make.name) < 0)
    {
        BUS_SET_OOM (error);
        return NULL;
    }

    _dbus_verbose("Return value '%s'\n", bus);
	return bus;
}

DBusServer* empty_server_init(char* address)
{
	return dbus_server_init_mini(address);
}

DBusConnection* daemon_as_client(DBusBusType type, char* address, DBusError *error)
{
	DBusConnection* connection;
	DBusString daemon_name;

	dbus_bus_set_bus_connection_address(type, address);

	connection = dbus_bus_get(type, error);
	if(connection == NULL)
		return NULL;

	_dbus_string_init_const(&daemon_name, DBUS_SERVICE_DBUS);
	if(!kdbus_register_policy (&daemon_name, connection))
		goto failed;

	if(kdbus_request_name(connection, &daemon_name, 0, 0) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
		goto failed;

//	dbus_bus_add_match(connection, "type='signal', member='NameAcquired'", error);  //not needed if request name ioctled  by daemon not libdbus
//	dbus_bus_add_match(connection, "type='signal', member='NameLost'", error);  //todo dispatch and digest this  or ioctl about name where daemon checks name presence
	if(!add_match_kdbus (dbus_connection_get_transport(connection), 1, "type='signal', member='NameLost'"))
	{
	      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for id:1, %s", _dbus_strerror_from_errno ());
	      return FALSE;
	}

	if(dbus_error_is_set(error))
	{
failed:
		_dbus_connection_close_possibly_shared (connection);
		dbus_connection_unref (connection);
		connection = NULL;
	}
	else
		_dbus_verbose ("Daemon connected as kdbus client.\n");

	return connection;
}

dbus_bool_t kdbus_register_policy (const DBusString *service_name, DBusConnection* connection)
{
	int fd;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

	return register_kdbus_policy(_dbus_string_get_const_data(service_name), fd);
}

dbus_uint32_t kdbus_request_name(DBusConnection* connection, const DBusString *service_name, dbus_uint32_t flags, __u64 sender_id)
{
	int fd;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

	return request_kdbus_name(fd, _dbus_string_get_const_data(service_name), flags, sender_id);
}

dbus_uint32_t kdbus_release_name(DBusConnection* connection, const DBusString *service_name, __u64 sender_id)
{
	int fd;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

	return release_kdbus_name(fd, _dbus_string_get_const_data(service_name), sender_id);
}

dbus_bool_t kdbus_list_services (DBusConnection* connection, char ***listp, int *array_len)
{
	int fd;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

	return list_kdbus_names(fd, listp, array_len);
}

dbus_bool_t kdbus_add_match_rule (DBusConnection* connection, DBusMessage* message, const char* text, DBusError* error)
{
	__u64 sender_id;

	sender_id = sender_name_to_id(dbus_message_get_sender(message), error);
	if(dbus_error_is_set(error))
		return FALSE;

	if(!add_match_kdbus (dbus_connection_get_transport(connection), sender_id, text))
	{
	      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for id:%d, %s",
	                      sender_id, _dbus_strerror_from_errno ());
	      return FALSE;
	}

	return TRUE;
}

dbus_bool_t kdbus_remove_match (DBusConnection* connection, DBusMessage* message, DBusError* error)
{
	__u64 sender_id;

	sender_id = sender_name_to_id(dbus_message_get_sender(message), error);
	if(dbus_error_is_set(error))
		return FALSE;

	if(!remove_match_kdbus (dbus_connection_get_transport(connection), sender_id))
	{
	      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not remove match rules for id:%d", sender_id);
	      return FALSE;
	}

	return TRUE;
}

dbus_bool_t kdbus_get_connection_unix_user(DBusConnection* connection, DBusMessage* message, unsigned long* uid, DBusError* error)
{
	char* name = NULL;
	struct nameInfo info;
	int inter_ret;
	dbus_bool_t ret = FALSE;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
	inter_ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
	if(inter_ret == 0) //name found
	{
		_dbus_verbose("User id:%llu\n", (unsigned long long) info.userId);
		*uid = info.userId;
		return TRUE;
	}
	else if(inter_ret == -ENOENT)  //name has no owner
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get UID of name '%s': no such name", name);
	else
	{
		_dbus_verbose("kdbus error determining UID: err %d (%m)\n", errno);
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine UID for '%s'", name);
	}

	return ret;
}

dbus_bool_t kdbus_get_connection_unix_process_id(DBusConnection* connection, DBusMessage* message, unsigned long* pid, DBusError* error)
{
	char* name = NULL;
	struct nameInfo info;
	int inter_ret;
	dbus_bool_t ret = FALSE;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
	inter_ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
	if(inter_ret == 0) //name found
	{
		_dbus_verbose("Process id:%llu\n", (unsigned long long) info.processId);
		*pid = info.processId;
		return TRUE;
	}
	else if(inter_ret == -ENOENT)  //name has no owner
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get PID of name '%s': no such name", name);
	else
	{
		_dbus_verbose("kdbus error determining PID: err %d (%m)\n", errno);
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine PID for '%s'", name);
	}

	return ret;
}

dbus_bool_t kdbus_get_connection_unix_selinux_security_context(DBusConnection* connection, DBusMessage* message, DBusMessage* reply, DBusError* error)
{
	char* name = NULL;
	struct nameInfo info;
	int inter_ret;
	dbus_bool_t ret = FALSE;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
	inter_ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
	if(inter_ret == -ENOENT)  //name has no owner
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get security context of name '%s': no such name", name);
	else if(inter_ret < 0)
	{
		_dbus_verbose("kdbus error determining security context: err %d (%m)\n", errno);
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine security context for '%s'", name);
	}
	else
	{
		if (!dbus_message_append_args (reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &info.sec_label, info.sec_label_len, DBUS_TYPE_INVALID))
		{
		      _DBUS_SET_OOM (error);
		      return FALSE;
		}
		ret = TRUE;
	}

	return ret;
}
