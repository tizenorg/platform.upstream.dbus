/*
 * kdbus-d.c
 *
 *  Created on: Sep 4, 2013
 *      Author: r.pajak
 *
 *  kdbus add-on to dbus daemon
 *
 */

#include <kdbus-d.h>
#include <dbus/kdbus.h>
#include <dbus/dbus-connection-internal.h>

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

DBusConnection* daemon_as_client(DBusBusType type, DBusError *error)
{
	DBusConnection* connection;

	connection = dbus_bus_get(type, error);
	if(connection == NULL)
		return NULL;

	if(dbus_bus_request_name(connection, DBUS_SERVICE_DBUS, 0, error) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
		goto failed;

	dbus_bus_add_match(connection, "type='signal', member='NameAcquired'", error);
	dbus_bus_add_match(connection, "type='signal', member='NameLost'", error);
	if(dbus_error_is_set(error))
		goto failed;

	return connection;

failed:
	_dbus_connection_close_possibly_shared (connection);
	dbus_connection_unref (connection);
	connection = NULL;
	return NULL;
}
