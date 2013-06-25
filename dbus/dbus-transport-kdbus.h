
#include "dbus-transport.h"
#include "dbus-transport-protected.h"
#include "dbus-address.h"
#include "dbus-errors.h"

DBusTransportOpenResult _dbus_transport_open_kdbus(DBusAddressEntry *entry, DBusTransport **transport_p, DBusError *error);
dbus_bool_t bus_register_kdbus(char** uniqe_name, DBusConnection *connection, DBusError *error);
