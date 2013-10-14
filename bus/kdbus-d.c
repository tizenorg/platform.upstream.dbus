/*
 * kdbus-d.c
 *
 *  Created on: Sep 4, 2013
 *      Author: r.pajak
 *
 *  kdbus add-on to dbus daemon
 *
 */

#include <dbus/dbus-connection-internal.h>
#include "kdbus-d.h"
#include <dbus/kdbus.h>
#include <dbus/dbus-bus.h>
#include "dispatch.h"
#include <dbus/kdbus-common.h>
#include <dbus/dbus-transport.h>
#include <dbus/dbus-transport-kdbus.h>
#include "connection.h"
#include "activation.h"
#include "services.h"

#include <utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

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

    _dbus_verbose("Opening /dev/kdbus/control\n");
    fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
    if (fdc < 0)
    {
        _dbus_verbose("--- error %d (%m)\n", fdc);
        dbus_set_error(error, DBUS_ERROR_FAILED, "Opening /dev/kdbus/control failed: %d (%m)", fdc);
        return NULL;
    }

    memset(&bus_make, 0, sizeof(bus_make));
    bus_make.head.bloom_size = 64;
    bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;

    if(type == DBUS_BUS_SYSTEM)
        snprintf(bus_make.name, sizeof(bus_make.name), "%u-kdbus-%s", getuid(), "system");
    else
        snprintf(bus_make.name, sizeof(bus_make.name), "%u-kdbus-%u", getuid(), getpid());
    bus_make.n_type = KDBUS_MAKE_NAME;
    bus_make.n_size = KDBUS_PART_HEADER_SIZE + strlen(bus_make.name) + 1;
    bus_make.head.size = sizeof(struct kdbus_cmd_bus_make) + bus_make.n_size;

    _dbus_verbose("Creating bus '%s'\n", bus_make.name);
    ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &bus_make);
    if (ret)
    {
        _dbus_verbose("--- error %d (%m)\n", ret);
        dbus_set_error(error, DBUS_ERROR_FAILED, "Creating bus '%s' failed: %d (%m)", bus_make.name, fdc);
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

	connection = dbus_bus_get_private(type, error);  /*todo possibly could be optimised by using lower functions*/
	if(connection == NULL)
		return NULL;

	_dbus_string_init_const(&daemon_name, DBUS_SERVICE_DBUS);
	if(!kdbus_register_policy (&daemon_name, connection))
		goto failed;

	if(kdbus_request_name(connection, &daemon_name, 0, 0) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
		goto failed;

    if(!add_match_kdbus (dbus_connection_get_transport(connection), 1, "member='IdRemoved'"))
    {
          dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for id:1, %s", _dbus_strerror_from_errno ());
          return FALSE;
    }
    if(!add_match_kdbus (dbus_connection_get_transport(connection), 1, "member='NameChanged'"))
    {
          dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for id:1, %s", _dbus_strerror_from_errno ());
          return FALSE;
    }
    if(!add_match_kdbus (dbus_connection_get_transport(connection), 1, "member='NameLost'"))
    {
          dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for id:1, %s", _dbus_strerror_from_errno ());
          return FALSE;
    }
    if(!add_match_kdbus (dbus_connection_get_transport(connection), 1, "member='NameAcquired'"))
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

DBusConnection* create_phantom_connection(DBusConnection* connection, const char* unique_name, DBusError* error)
{
    DBusConnection *phantom_connection;
    DBusString name;

    _dbus_string_init_const(&name, unique_name);

    phantom_connection = _dbus_connection_new_for_used_transport (dbus_connection_get_transport(connection));
    if(phantom_connection == NULL)
        return FALSE;
    if(!bus_connections_setup_connection(bus_connection_get_connections(connection), phantom_connection))
    {
        dbus_connection_unref_phantom(phantom_connection);
        phantom_connection = NULL;
        dbus_set_error (error, DBUS_ERROR_FAILED , "Name \"%s\" could not be acquired", unique_name);
        goto out;
    }
    if(!bus_connection_complete(phantom_connection, &name, error))
    {
        bus_connection_disconnected(phantom_connection);
        phantom_connection = NULL;
        goto out;
    }

    _dbus_verbose ("Created phantom connection for %s\n", bus_connection_get_name(phantom_connection));

out:
    return phantom_connection;
}

dbus_bool_t register_kdbus_starters(DBusConnection* connection)
{
    int i,j, len;
    char **services;
    dbus_bool_t retval = FALSE;
    int fd;
    BusTransaction *transaction;
    DBusString name;

    transaction = bus_transaction_new (bus_connection_get_context(connection));
    if (transaction == NULL)
    	return FALSE;

    if (!bus_activation_list_services (bus_connection_get_activation (connection), &services, &len))
        return FALSE;

    _dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);
    _dbus_string_init(&name);

    for(i=0; i<len; i++)
    {
        if(!register_kdbus_policy(services[i], fd))
            goto out;

        if (request_kdbus_name(fd, services[i], (DBUS_NAME_FLAG_ALLOW_REPLACEMENT | KDBUS_NAME_STARTER) , 0) < 0)
            goto out;

        if(!_dbus_string_append(&name, services[i]))
        	goto out;
        if(!bus_registry_ensure (bus_connection_get_registry (connection), &name, connection,
        		(DBUS_NAME_FLAG_ALLOW_REPLACEMENT | KDBUS_NAME_STARTER), transaction, NULL))
        	goto out;
        if(!_dbus_string_set_length(&name, 0))
        	goto out;
    }
    retval = TRUE;

out:
	for(j=0; j<i; j++)
		release_kdbus_name(fd, services[j], 0);
    dbus_free_string_array (services);
    _dbus_string_free(&name);
    bus_transaction_free(transaction);
    return retval;
}

/*
static dbus_bool_t remove_conn_if_name_match (DBusConnection *connection, void *data)
{
    if(!strcmp(bus_connection_get_name(connection), (char*)data))
    {
        bus_connection_disconnected(connection);
        return FALSE; //this is to break foreach function
    }
    return TRUE;
}*/

void handleNameOwnerChanged(DBusMessage *msg, BusTransaction *transaction, DBusConnection *connection)
{
    const char *name, *old, *new;

    if(!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old, DBUS_TYPE_STRING, &new, DBUS_TYPE_INVALID))
    {
        _dbus_verbose ("Couldn't get args of NameOwnerChanged signal: .\n");//, error.message);
        return;
    }

    _dbus_verbose ("Got NameOwnerChanged signal:\nName: %s\nOld: %s\nNew: %s\n", name, old, new);

    if(!strncmp(name, ":1.", 3))/*if it starts from :1. it is unique name - this might be IdRemoved info*/
    {
        if(!strcmp(name, old))  //yes it is - someone has disconnected
        {
            DBusConnection* conn;

            conn = bus_connections_find_conn_by_name(bus_connection_get_connections(connection), name);
            if(conn)
                bus_connection_disconnected(conn);
        }
    }
    else //it is well-known name
    {
        if((*old != 0) && (strcmp(old, ":1.1")))
        {
            DBusMessage *message;

            if(bus_connections_find_conn_by_name(bus_connection_get_connections(connection), old) == NULL)
                goto next;

            _dbus_verbose ("Owner '%s' lost name '%s'. Sending NameLost.\n", old, name);

            message = dbus_message_new_signal (DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameLost");
            if (message == NULL)
                goto next;

            if (!dbus_message_set_destination (message, old) || !dbus_message_append_args (message,
                                                                 DBUS_TYPE_STRING, &name,
                                                                 DBUS_TYPE_INVALID))
            {
                dbus_message_unref (message);
                goto next;
            }

            bus_transaction_send_from_driver (transaction, connection, message);
            dbus_message_unref (message);
        }
    next:
        if((*new != 0) && (strcmp(new, ":1.1")))
        {
            DBusMessage *message;

            _dbus_verbose ("Owner '%s' acquired name '%s'. Sending NameAcquired.\n", new, name);

            message = dbus_message_new_signal (DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameAcquired");
            if (message == NULL)
                return;

            if (!dbus_message_set_destination (message, new) || !dbus_message_append_args (message,
                                                                 DBUS_TYPE_STRING, &name,
                                                                 DBUS_TYPE_INVALID))
            {
                dbus_message_unref (message);
                return;
            }

            bus_transaction_send_from_driver (transaction, connection, message);
            dbus_message_unref (message);
        }
    }
}