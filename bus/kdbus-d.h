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
#include <bus.h>


char* make_kdbus_bus(DBusBusType type, DBusError *error);
DBusConnection* daemon_as_client(DBusBusType type, DBusError *error);


#endif /* KDBUS_H_ */
