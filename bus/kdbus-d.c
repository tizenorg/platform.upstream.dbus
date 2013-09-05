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
#include <dbus/dbus-connection-internal.h>

dbus_bool_t make_kdbus_bus(DBusBusType type, DBusError *error)
{

	return TRUE;
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
