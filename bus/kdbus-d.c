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

#include <utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

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

DBusServer* fake_server(char* address)
{
	return dbus_server_init_mini(address);
}

DBusConnection* daemon_as_client(DBusBusType type, char* address, DBusError *error)
{
	DBusConnection* connection;

	dbus_bus_set_bus_connection_address(type, address);

	connection = dbus_bus_get(type, error);
	if(connection == NULL)
		return NULL;

	if(dbus_bus_request_name(connection, DBUS_SERVICE_DBUS, 0, error) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
		goto failed;

	dbus_bus_add_match(connection, "type='signal', member='NameAcquired'", error);
	dbus_bus_add_match(connection, "type='signal', member='NameLost'", error);
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

dbus_bool_t setup_connection(BusContext* context, DBusError* error)
{
	//on the basis of bus_connections_setup_connection from connection.c

	dbus_bool_t retval = FALSE; //todo opitimize
//	DBusConnection* connection;

	//todo what to do with error

/*	connection = context->myConnection;  //todo
	dbus_connection_set_route_peer_messages (connection, TRUE);

	if (!dbus_connection_set_watch_functions (connection,
											add_connection_watch,
											remove_connection_watch,
											toggle_connection_watch,
											connection,
											NULL))
		goto out;

	if (!dbus_connection_set_timeout_functions (connection,
											  add_connection_timeout,
											  remove_connection_timeout,
											  NULL,
											  connection, NULL))
		goto out;

	dbus_connection_set_dispatch_status_function (connection,
												dispatch_status_function,
												bus_context_get_loop (context),
												NULL);

	if (!bus_dispatch_add_connection (connection))
		goto out;

	retval = TRUE;

	out:
	if (!retval)
	{
	  if (!dbus_connection_set_watch_functions (connection,
												NULL, NULL, NULL,
												connection,
												NULL))
		_dbus_assert_not_reached ("setting watch functions to NULL failed");

	  if (!dbus_connection_set_timeout_functions (connection,
												  NULL, NULL, NULL,
												  connection,
												  NULL))
		_dbus_assert_not_reached ("setting timeout functions to NULL failed");


	  dbus_connection_set_dispatch_status_function (connection,
													NULL, NULL, NULL);
	}
*/
	return retval;
}
