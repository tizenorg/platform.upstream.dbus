
#include "dbus-transport.h"
#include "dbus-transport-protected.h"
#include "dbus-address.h"
#include "dbus-errors.h"
#include "dbus-types.h"

dbus_bool_t dbus_transport_is_kdbus(DBusConnection *connection);
DBusTransportOpenResult _dbus_transport_open_kdbus(DBusAddressEntry *entry, DBusTransport **transport_p, DBusError *error);
dbus_bool_t bus_register_kdbus(char* name, DBusConnection *connection, DBusError *error);
dbus_bool_t bus_register_policy_kdbus(const char* name, DBusConnection *connection, DBusError *error);
int bus_request_name_kdbus(DBusConnection *connection, const char *name, const uint64_t flags, DBusError *error);
void dbus_bus_add_match_kdbus (DBusConnection *connection, const char *rule, DBusError *error);
void dbus_bus_remove_match_kdbus (DBusConnection *connection, DBusError *error);
