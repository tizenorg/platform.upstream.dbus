
#include "dbus-transport.h"
#include "dbus-transport-protected.h"
#include "dbus-address.h"
#include "dbus-errors.h"
#include "dbus-types.h"

dbus_bool_t dbus_transport_is_kdbus(DBusConnection *connection);
DBusTransportOpenResult _dbus_transport_open_kdbus(DBusAddressEntry *entry, DBusTransport **transport_p, DBusError *error);
dbus_bool_t bus_register_kdbus(char** uniqe_name, DBusConnection *connection, DBusError *error);
dbus_bool_t bus_register_kdbus_policy(const char* name, DBusConnection *connection, DBusError *error);
uint64_t bus_request_name_kdbus(DBusConnection *connection, const char *name, const uint64_t flags, DBusError *error);
