/*
 * kdbus_common.h
 *
 *  Created on: Sep 13, 2013
 *      Author: r.pajak
 *
 *  Kdbus internal util functions used by daemon and libdbus
 */

#ifndef KDBUS_COMMON_H_
#define KDBUS_COMMON_H_

#include <dbus/dbus-types.h>
#include <dbus/dbus-transport.h>

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_PART_NEXT(part) \
	(typeof(part))(((uint8_t *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_PART_HEADER_SIZE)

/*struct kdbus_policy *make_policy_name(const char *name);
struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id);
void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size);*/
dbus_bool_t register_kdbus_policy(const char* name, int fd);
dbus_bool_t list_kdbus_names(int fd, char ***listp, int *array_len);
int request_kdbus_name(int fd, const char *name, const __u64 flags, __u64 id);
int release_kdbus_name(int fd, const char *name, __u64 id);

#endif /* KDBUS_COMMON_H_ */
