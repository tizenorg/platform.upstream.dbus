
#ifndef DBUS_TRANSPORT_KDBUS_H_
#define DBUS_TRANSPORT_KDBUS_H_

//#include "dbus-transport.h"
#include "dbus-transport-protected.h"
//#include "dbus-address.h"
//#include "dbus-errors.h"
#include "dbus-types.h"
#include <linux/types.h>

struct nameInfo
{
	__u64 uniqueId;
	__u64 userId;
	__u64 processId;
	__u32 sec_label_len;
	char *sec_label;
};

DBusTransportOpenResult _dbus_transport_open_kdbus(DBusAddressEntry *entry, DBusTransport **transport_p, DBusError *error);
dbus_bool_t add_match_kdbus (DBusTransport* transport, __u64 id, const char *rule);
dbus_bool_t remove_match_kdbus (DBusTransport* transport, __u64 id);
int kdbus_NameQuery(const char* name, DBusTransport* transport, struct nameInfo* pInfo);

#endif
