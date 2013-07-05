/*
 * dbus-transport-kdbus.c
 *
 * Transport layer using kdbus
 *
 *  Created on: Jun 20, 2013
 *      Author: r.pajak
 *
 *
 */

#include "dbus-transport.h"
#include "dbus-transport-kdbus.h"
#include <dbus/dbus-transport-protected.h>
#include "dbus-connection-internal.h"
#include "kdbus.h"
#include "dbus-watch.h"
#include "dbus-errors.h"
#include "dbus-bus.h"
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/types.h>

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_PART_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_PART_HEADER_SIZE)

#define KDBUS_PART_NEXT(part) \
	(typeof(part))(((uint8_t *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_PART_FOREACH(part, head, first)				\
	for (part = (head)->first;					\
	     (uint8_t *)(part) < (uint8_t *)(head) + (head)->size;	\
	     part = KDBUS_PART_NEXT(part))
#define POOL_SIZE (16 * 1024LU * 1024LU)

/*struct and type below copied from dbus_transport_socket.c
 * needed for _dbus_transport_new_for_socket_kdbus and kdbus_vtable(?)
 * todo maybe DBusTransportSocket and _dbus_transport_new_for_socket_kdbus not needed here -
 * maybe only static const DBusTransportVTable implementation will be enough
 */

/**
 * Opaque object representing a socket file descriptor transport.
 */
typedef struct DBusTransportSocket DBusTransportSocket;

/**
 * Implementation details of DBusTransportSocket. All members are private.
 */
struct DBusTransportSocket
{
  DBusTransport base;                   /**< Parent instance */
  int fd;                               /**< File descriptor. */
  DBusWatch *read_watch;                /**< Watch for readability. */
  DBusWatch *write_watch;               /**< Watch for writability. */

  int max_bytes_read_per_iteration;     /**< To avoid blocking too long. */
  int max_bytes_written_per_iteration;  /**< To avoid blocking too long. */

  int message_bytes_written;            /**< Number of bytes of current
                                         *   outgoing message that have
                                         *   been written.
                                         */
  DBusString encoded_outgoing;          /**< Encoded version of current
                                         *   outgoing message.
                                         */
  DBusString encoded_incoming;          /**< Encoded version of current
                                         *   incoming data.
                                         */
  void* kdbus_mmap_ptr;
};


//prototypes of local functions, needed for compiler
int _dbus_connect_kdbus (const char *path, DBusError *error);
DBusTransport* _dbus_transport_new_for_kdbus (const char *path, DBusError *error);
DBusTransport* _dbus_transport_new_for_socket_kdbus (int fd, const DBusString *server_guid, const DBusString *address);
struct kdbus_policy *make_policy_name(const char *name);
struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id);
void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size);
int kdbus_write_msg(DBusConnection *connection, DBusMessage *message, int fd);
int kdbus_write_msg_encoded(DBusMessage *message, DBusTransportSocket *socket_transport);
dbus_bool_t kdbus_mmap(DBusTransport* transport);
int kdbus_read_message(DBusTransportSocket *socket_transport, DBusString *buffer);
int kdbus_decode_msg(const struct kdbus_msg* msg, char *data, void* mmap_ptr);

static dbus_bool_t
socket_get_socket_fd (DBusTransport *transport,
                      int           *fd_p)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  *fd_p = socket_transport->fd;

  return TRUE;
}

int kdbus_write_msg(DBusConnection *connection, DBusMessage *message, int fd)
{
	struct kdbus_msg *msg;
	struct kdbus_item *item;
	uint64_t size;
	const char *name;
	uint64_t dst_id = KDBUS_DST_ID_BROADCAST;
    const DBusString *header;
    const DBusString *body;
    uint64_t ret_size;

//    uint64_t i;

    if((name = dbus_message_get_destination(message)))
    {
    	_dbus_verbose ("do writing destination: %s\n", name); //todo can be removed at the end
    	dst_id = KDBUS_DST_ID_WELL_KNOWN_NAME;
    	if((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))
    	{
    		dst_id = strtoll(&name[3], NULL, 10);
    		_dbus_verbose ("do writing uniqe id: %lu\n", dst_id); //todo can be removed at the end
    		name = NULL;
    	}
    }

    _dbus_message_get_network_data (message, &header, &body);
    ret_size = (uint64_t)_dbus_string_get_length(header);

  /*  fprintf (stderr, "\nheader:\n");
    for(i=0; i < ret_size; i++)
    {
    	fprintf (stderr, "%02x", _dbus_string_get_byte(header,i));
    }
    fprintf (stderr, "\nret size: %lu, i: %lu\n", ret_size, i);*/

//    _dbus_verbose("padding bytes for header: %lu \n", KDBUS_ALIGN8(ret_size) - ret_size);

    size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
//	if(KDBUS_ALIGN8(ret_size) - ret_size)  //if padding needed
//		size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));  //additional structure for padding null bytes
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	if (dst_id == KDBUS_DST_ID_BROADCAST)
		size += KDBUS_PART_HEADER_SIZE + 64;

	if (name)
		size += KDBUS_ITEM_SIZE(strlen(name) + 1);

	msg = malloc(size);
	if (!msg)
	{
		_dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
		return -1;
	}

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = strtoll(dbus_bus_get_unique_name(connection), NULL , 10);
	_dbus_verbose("sending msg, src_id=%llu\n", msg->src_id);
	msg->dst_id = name ? 0 : dst_id;
	msg->cookie = dbus_message_get_serial(message);
	msg->payload_type = KDBUS_PAYLOAD_DBUS1;

	item = msg->items;

	if (name)
	{
		item->type = KDBUS_MSG_DST_NAME;
		item->size = KDBUS_PART_HEADER_SIZE + strlen(name) + 1;
		strcpy(item->str, name);
		item = KDBUS_PART_NEXT(item);
	}

	item->type = KDBUS_MSG_PAYLOAD_VEC;
	item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uint64_t)_dbus_string_get_const_data(header);
	item->vec.size = ret_size;
	item = KDBUS_PART_NEXT(item);

/*	if(KDBUS_ALIGN8(ret_size) - ret_size)
	{
		item->type = KDBUS_MSG_PAYLOAD_VEC;
		item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_vec);
		item->vec.address = (uint64_t)NULL;
		item->vec.size = KDBUS_ALIGN8(ret_size) - ret_size;
		item = KDBUS_PART_NEXT(item);
	}*/

	item->type = KDBUS_MSG_PAYLOAD_VEC;
	item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uint64_t)_dbus_string_get_const_data(body);
	item->vec.size = (uint64_t)_dbus_string_get_length(body);
	ret_size += item->vec.size;

  /*  fprintf (stderr, "\nbody:\n");
    for(i=0; i < item->vec.size; i++)
    {
    	fprintf (stderr, "%02x", _dbus_string_get_byte(body,i));
    }
    fprintf (stderr, "\nitem->vec.size: %llu, i: %lu\n", item->vec.size, i);*/


	item = KDBUS_PART_NEXT(item);



	if (dst_id == KDBUS_DST_ID_BROADCAST)
	{
		item->type = KDBUS_MSG_BLOOM;
		item->size = KDBUS_PART_HEADER_SIZE + 64;
	}

	again:
	if (ioctl(fd, KDBUS_CMD_MSG_SEND, msg))
	{
		if(errno == EINTR)
			goto again;
		_dbus_verbose("kdbus error sending message: err %d (%m)\n", errno);
		return -1;
	}

	free(msg);

	return ret_size;
}

int kdbus_write_msg_encoded(DBusMessage *message, DBusTransportSocket *socket_transport)
{
	struct kdbus_msg *msg;
	struct kdbus_item *item;
	uint64_t size;
	const char *name;
	uint64_t dst_id = KDBUS_DST_ID_BROADCAST;
    uint64_t ret_size;

    if((name = dbus_message_get_destination(message)))
    {
    	_dbus_verbose ("do writing encoded message destination: %s\n", name); //todo can be removed at the end
    	if((name[0] == '1') && (name[1] == ':'))
    	{
    		dst_id = strtoll(&name[2], NULL, 10);
    		_dbus_verbose ("do writing encoded message uniqe id form name: %lu\n", dst_id); //todo can be removed at the end
    		name = NULL;
    	}
    }

    size = sizeof(struct kdbus_msg);
	size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	if (dst_id == KDBUS_DST_ID_BROADCAST)
		size += KDBUS_PART_HEADER_SIZE + 64;

	if (name)
		size += KDBUS_ITEM_SIZE(strlen(name) + 1);

	msg = malloc(size);
	if (!msg)
	{
		_dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
		return -1;
	}

	memset(msg, 0, size);
	msg->size = size;
	msg->src_id = strtoll(dbus_bus_get_unique_name(socket_transport->base.connection), NULL , 10);
	_dbus_verbose("sending encoded msg, src_id=%llu\n", msg->src_id);
	msg->dst_id = name ? 0 : dst_id;
	msg->cookie = dbus_message_get_serial(message);
	msg->payload_type = KDBUS_PAYLOAD_DBUS1;

	item = msg->items;

	if (name)
	{
		item->type = KDBUS_MSG_DST_NAME;
		item->size = KDBUS_PART_HEADER_SIZE + strlen(name) + 1;
		strcpy(item->str, name);
		item = KDBUS_PART_NEXT(item);
	}

	item->type = KDBUS_MSG_PAYLOAD_VEC;
	item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->vec.address = (uint64_t)&socket_transport->encoded_outgoing;
	item->vec.size = _dbus_string_get_length (&socket_transport->encoded_outgoing);
	item = KDBUS_PART_NEXT(item);

	if (dst_id == KDBUS_DST_ID_BROADCAST)
	{
		item->type = KDBUS_MSG_BLOOM;
		item->size = KDBUS_PART_HEADER_SIZE + 64;
	}

	again:
	if (ioctl(socket_transport->fd, KDBUS_CMD_MSG_SEND, msg))
	{
		if(errno == EINTR)
			goto again;
		_dbus_verbose("error sending encoded message: err %d (%m)\n", errno);
		return -1;
	}

	free(msg);

	return ret_size;
}

//todo functions from kdbus-utli.c for printing messages - maybe to remove at the end
char *msg_id(uint64_t id, char *buf);
char *msg_id(uint64_t id, char *buf)
{
	if (id == 0)
		return "KERNEL";
	if (id == ~0ULL)
		return "BROADCAST";
	sprintf(buf, "%llu", (unsigned long long)id);
	return buf;
}

struct kdbus_enum_table {
	long long id;
	const char *name;
};
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))
#define TABLE(what) static struct kdbus_enum_table kdbus_table_##what[]
#define ENUM(_id) { .id=_id, .name=STRINGIFY(_id) }
#define LOOKUP(what)								\
	const char *enum_##what(long long id) {					\
	size_t i; \
		for (i = 0; i < ELEMENTSOF(kdbus_table_##what); i++)	\
			if (id == kdbus_table_##what[i].id)			\
				return kdbus_table_##what[i].name;		\
		return "UNKNOWN";						\
	}
const char *enum_MSG(long long id);
TABLE(MSG) = {
	ENUM(_KDBUS_MSG_NULL),
	ENUM(KDBUS_MSG_PAYLOAD_VEC),
	ENUM(KDBUS_MSG_PAYLOAD_OFF),
	ENUM(KDBUS_MSG_PAYLOAD_MEMFD),
	ENUM(KDBUS_MSG_FDS),
	ENUM(KDBUS_MSG_BLOOM),
	ENUM(KDBUS_MSG_DST_NAME),
	ENUM(KDBUS_MSG_SRC_CREDS),
	ENUM(KDBUS_MSG_SRC_PID_COMM),
	ENUM(KDBUS_MSG_SRC_TID_COMM),
	ENUM(KDBUS_MSG_SRC_EXE),
	ENUM(KDBUS_MSG_SRC_CMDLINE),
	ENUM(KDBUS_MSG_SRC_CGROUP),
	ENUM(KDBUS_MSG_SRC_CAPS),
	ENUM(KDBUS_MSG_SRC_SECLABEL),
	ENUM(KDBUS_MSG_SRC_AUDIT),
	ENUM(KDBUS_MSG_SRC_NAMES),
	ENUM(KDBUS_MSG_TIMESTAMP),
	ENUM(KDBUS_MSG_NAME_ADD),
	ENUM(KDBUS_MSG_NAME_REMOVE),
	ENUM(KDBUS_MSG_NAME_CHANGE),
	ENUM(KDBUS_MSG_ID_ADD),
	ENUM(KDBUS_MSG_ID_REMOVE),
	ENUM(KDBUS_MSG_REPLY_TIMEOUT),
	ENUM(KDBUS_MSG_REPLY_DEAD),
};
LOOKUP(MSG);
const char *enum_PAYLOAD(long long id);
TABLE(PAYLOAD) = {
	ENUM(KDBUS_PAYLOAD_KERNEL),
	ENUM(KDBUS_PAYLOAD_DBUS1),
	ENUM(KDBUS_PAYLOAD_GVARIANT),
};
LOOKUP(PAYLOAD);

  //todo handling of all msg items
int kdbus_decode_msg(const struct kdbus_msg* msg, char *data, void* mmap_ptr)
{
	const struct kdbus_item *item = msg->items;
	char buf[32];
	int ret_size = 0;

	_dbus_verbose("MESSAGE: %s (%llu bytes) flags=0x%llx, %s → %s, cookie=%llu, timeout=%llu\n",
		enum_PAYLOAD(msg->payload_type), (unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		msg_id(msg->src_id, buf), msg_id(msg->dst_id, buf),
		(unsigned long long) msg->cookie, (unsigned long long) msg->timeout_ns);

	KDBUS_PART_FOREACH(item, msg, items)
	{
		if (item->size <= KDBUS_PART_HEADER_SIZE) {
			_dbus_verbose("  +%s (%llu bytes) invalid data record\n", enum_MSG(item->type), item->size);
			break;  //todo to be discovered and rewritten
		}

		switch (item->type)
		{
			case KDBUS_MSG_PAYLOAD_OFF:
			{
				char *s;

				if (item->vec.offset == ~0ULL)
					s = "[padding bytes]";
				else
				{
//					uint64_t i;

					s = (char *)mmap_ptr + item->vec.offset;
				/*	fprintf(stderr,"\nmmap: %lu", (uint64_t)mmap_ptr);
					fprintf (stderr, "\nheader: %llu\n", item->vec.size);
				    for(i=0; i < item->vec.size; i++)
				    {
				    	fprintf (stderr, "%02x", (int)s[i]);
				    }
				    fprintf (stderr, "\nret size: %llu, i: %lu\n", item->vec.size, i);*/

					memcpy(data, s, item->vec.size);
					data += item->vec.size;
					ret_size += item->vec.size;
				}

				_dbus_verbose("  +%s (%llu bytes) off=%llu size=%llu '%s'\n",
					   enum_MSG(item->type), item->size,
					   (unsigned long long)item->vec.offset,
					   (unsigned long long)item->vec.size, s);
				break;
			}

			case KDBUS_MSG_PAYLOAD_MEMFD:
			{
				char *buf;
				uint64_t size;

				buf = mmap(NULL, item->memfd.size, PROT_READ, MAP_SHARED, item->memfd.fd, 0);
				if (buf == MAP_FAILED) {
					_dbus_verbose("mmap() fd=%i failed:%m", item->memfd.fd);
					break;
				}

				if (ioctl(item->memfd.fd, KDBUS_CMD_MEMFD_SIZE_GET, &size) < 0) {
					_dbus_verbose("KDBUS_CMD_MEMFD_SIZE_GET failed: %m\n");
					break;
				}

				_dbus_verbose("  +%s (%llu bytes) fd=%i size=%llu filesize=%llu '%s'\n",
					   enum_MSG(item->type), item->size, item->memfd.fd,
					   (unsigned long long)item->memfd.size, (unsigned long long)size, buf);
				break;
			}

			case KDBUS_MSG_SRC_CREDS:
				_dbus_verbose("  +%s (%llu bytes) uid=%lld, gid=%lld, pid=%lld, tid=%lld, starttime=%lld\n",
					enum_MSG(item->type), item->size,
					item->creds.uid, item->creds.gid,
					item->creds.pid, item->creds.tid,
					item->creds.starttime);
			break;

			case KDBUS_MSG_SRC_PID_COMM:
			case KDBUS_MSG_SRC_TID_COMM:
			case KDBUS_MSG_SRC_EXE:
			case KDBUS_MSG_SRC_CGROUP:
			case KDBUS_MSG_SRC_SECLABEL:
			case KDBUS_MSG_DST_NAME:
				_dbus_verbose("  +%s (%llu bytes) '%s' (%zu)\n",
					   enum_MSG(item->type), item->size, item->str, strlen(item->str));
				break;

			case KDBUS_MSG_SRC_CMDLINE:
			case KDBUS_MSG_SRC_NAMES: {
				size_t size = item->size - KDBUS_PART_HEADER_SIZE;
				const char *str = item->str;
				int count = 0;

				_dbus_verbose("  +%s (%llu bytes) ", enum_MSG(item->type), item->size);
				while (size) {
					_dbus_verbose("'%s' ", str);
					size -= strlen(str) + 1;
					str += strlen(str) + 1;
					count++;
				}

				_dbus_verbose("(%d string%s)\n", count, (count == 1) ? "" : "s");
				break;
			}

			case KDBUS_MSG_SRC_AUDIT:
				_dbus_verbose("  +%s (%llu bytes) loginuid=%llu sessionid=%llu\n",
					   enum_MSG(item->type), item->size,
					   (unsigned long long)item->data64[0],
					   (unsigned long long)item->data64[1]);
				break;

			case KDBUS_MSG_SRC_CAPS: {
				int n;
				const uint32_t *cap;
				int i;

				_dbus_verbose("  +%s (%llu bytes) len=%llu bytes)\n",
					   enum_MSG(item->type), item->size,
					   (unsigned long long)item->size - KDBUS_PART_HEADER_SIZE);

				cap = item->data32;
				n = (item->size - KDBUS_PART_HEADER_SIZE) / 4 / sizeof(uint32_t);

				_dbus_verbose("    CapInh=");
				for (i = 0; i < n; i++)
					_dbus_verbose("%08x", cap[(0 * n) + (n - i - 1)]);

				_dbus_verbose(" CapPrm=");
				for (i = 0; i < n; i++)
					_dbus_verbose("%08x", cap[(1 * n) + (n - i - 1)]);

				_dbus_verbose(" CapEff=");
				for (i = 0; i < n; i++)
					_dbus_verbose("%08x", cap[(2 * n) + (n - i - 1)]);

				_dbus_verbose(" CapInh=");
				for (i = 0; i < n; i++)
					_dbus_verbose("%08x", cap[(3 * n) + (n - i - 1)]);
				_dbus_verbose("\n");
				break;
			}

			case KDBUS_MSG_TIMESTAMP:
				_dbus_verbose("  +%s (%llu bytes) realtime=%lluns monotonic=%lluns\n",
					   enum_MSG(item->type), item->size,
					   (unsigned long long)item->timestamp.realtime_ns,
					   (unsigned long long)item->timestamp.monotonic_ns);
				break;

			case KDBUS_MSG_REPLY_TIMEOUT:
				_dbus_verbose("  +%s (%llu bytes) cookie=%llu\n",
					   enum_MSG(item->type), item->size, msg->cookie_reply);
				break;

			case KDBUS_MSG_NAME_ADD:
			case KDBUS_MSG_NAME_REMOVE:
			case KDBUS_MSG_NAME_CHANGE:
				_dbus_verbose("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, flags=0x%llx\n",
					enum_MSG(item->type), (unsigned long long) item->size,
					item->name_change.name, item->name_change.old_id,
					item->name_change.new_id, item->name_change.flags);
			break;

			case KDBUS_MSG_ID_ADD:
			case KDBUS_MSG_ID_REMOVE:
				_dbus_verbose("  +%s (%llu bytes) id=%llu flags=%llu\n",
					   enum_MSG(item->type), (unsigned long long) item->size,
					   (unsigned long long) item->id_change.id,
					   (unsigned long long) item->id_change.flags);
			break;

			default:
				_dbus_verbose("  +%s (%llu bytes)\n", enum_MSG(item->type), item->size);
				break;
		}
	}

	if ((char *)item - ((char *)msg + msg->size) >= 8)
		_dbus_verbose("invalid padding at end of message\n");

	return ret_size;
}

int kdbus_read_message(DBusTransportSocket *socket_transport, DBusString *buffer)
{
	int ret_size;
	uint64_t offset;
	struct kdbus_msg *msg;
	int ret;
	int start;
	char *data;

//	int i;

	//todo this block maybe can be removed
	_dbus_assert (socket_transport->max_bytes_read_per_iteration >= 0);
	start = _dbus_string_get_length (buffer);
	if (!_dbus_string_lengthen (buffer, socket_transport->max_bytes_read_per_iteration))
	{
		errno = ENOMEM;
	    return -1;
	}
	data = _dbus_string_get_data_len (buffer, start, socket_transport->max_bytes_read_per_iteration);

	again:
	ret = ioctl(socket_transport->fd, KDBUS_CMD_MSG_RECV, &offset);
	if (ret < 0)
	{
		if(errno == EINTR)
			goto again;
		_dbus_verbose("kdbus error receiving message: %d (%m)\n", ret);
		_dbus_string_set_length (buffer, start);  //todo probably to remove
		return -1;
	}

	msg = (struct kdbus_msg *)((char*)socket_transport->kdbus_mmap_ptr + offset);

	ret_size = kdbus_decode_msg(msg, data, socket_transport->kdbus_mmap_ptr); //todo data to be replaced by buffer
/*	fprintf (stderr, "\nmessage! start: %u, ret_size: %u\n", start, ret_size);
    for(i=0; i < ret_size; i++)
    {
    	fprintf (stderr, "%02x", (int)data[i]);
    }
    fprintf (stderr, "\nret size: %u, i: %u\n", ret_size, i);*/
	_dbus_string_set_length (buffer, start + ret_size);

	again2:
	ret = ioctl(socket_transport->fd, KDBUS_CMD_MSG_RELEASE, &offset);
	if (ret < 0)
	{
		if(errno == EINTR)
			goto again2;
		_dbus_verbose("kdbus error freeing message: %d (%m)\n", ret);
		return -1;
	}

	return ret_size;
}

static void
free_watches (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  _dbus_verbose ("start\n");

  if (socket_transport->read_watch)
    {
      if (transport->connection)
        _dbus_connection_remove_watch_unlocked (transport->connection,
                                                socket_transport->read_watch);
      _dbus_watch_invalidate (socket_transport->read_watch);
      _dbus_watch_unref (socket_transport->read_watch);
      socket_transport->read_watch = NULL;
    }

  if (socket_transport->write_watch)
    {
      if (transport->connection)
        _dbus_connection_remove_watch_unlocked (transport->connection,
                                                socket_transport->write_watch);
      _dbus_watch_invalidate (socket_transport->write_watch);
      _dbus_watch_unref (socket_transport->write_watch);
      socket_transport->write_watch = NULL;
    }

  _dbus_verbose ("end\n");
}

static void
socket_finalize (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  _dbus_verbose ("\n");

  free_watches (transport);

  _dbus_string_free (&socket_transport->encoded_outgoing);
  _dbus_string_free (&socket_transport->encoded_incoming);

  _dbus_transport_finalize_base (transport);

  _dbus_assert (socket_transport->read_watch == NULL);
  _dbus_assert (socket_transport->write_watch == NULL);

  dbus_free (transport);
}

static void
check_write_watch (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  dbus_bool_t needed;

  if (transport->connection == NULL)
    return;

  if (transport->disconnected)
    {
      _dbus_assert (socket_transport->write_watch == NULL);
      return;
    }

  _dbus_transport_ref (transport);

  if (_dbus_transport_get_is_authenticated (transport))
    needed = _dbus_connection_has_messages_to_send_unlocked (transport->connection);
  else
    {
      if (transport->send_credentials_pending)
        needed = TRUE;
      else
        {
          DBusAuthState auth_state;

          auth_state = _dbus_auth_do_work (transport->auth);

          /* If we need memory we install the write watch just in case,
           * if there's no need for it, it will get de-installed
           * next time we try reading.
           */
          if (auth_state == DBUS_AUTH_STATE_HAVE_BYTES_TO_SEND ||
              auth_state == DBUS_AUTH_STATE_WAITING_FOR_MEMORY)
            needed = TRUE;
          else
            needed = FALSE;
        }
    }

  _dbus_verbose ("check_write_watch(): needed = %d on connection %p watch %p fd = %d outgoing messages exist %d\n",
                 needed, transport->connection, socket_transport->write_watch,
                 socket_transport->fd,
                 _dbus_connection_has_messages_to_send_unlocked (transport->connection));

  _dbus_connection_toggle_watch_unlocked (transport->connection,
                                          socket_transport->write_watch,
                                          needed);

  _dbus_transport_unref (transport);
}

static void
check_read_watch (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  dbus_bool_t need_read_watch;

  _dbus_verbose ("fd = %d\n",socket_transport->fd);

  if (transport->connection == NULL)
    return;

  if (transport->disconnected)
    {
      _dbus_assert (socket_transport->read_watch == NULL);
      return;
    }

  _dbus_transport_ref (transport);

  if (_dbus_transport_get_is_authenticated (transport))
    need_read_watch =
      (_dbus_counter_get_size_value (transport->live_messages) < transport->max_live_messages_size) &&
      (_dbus_counter_get_unix_fd_value (transport->live_messages) < transport->max_live_messages_unix_fds);
  else
    {
      if (transport->receive_credentials_pending)
        need_read_watch = TRUE;
      else
        {
          /* The reason to disable need_read_watch when not WAITING_FOR_INPUT
           * is to avoid spinning on the file descriptor when we're waiting
           * to write or for some other part of the auth process
           */
          DBusAuthState auth_state;

          auth_state = _dbus_auth_do_work (transport->auth);

          /* If we need memory we install the read watch just in case,
           * if there's no need for it, it will get de-installed
           * next time we try reading. If we're authenticated we
           * install it since we normally have it installed while
           * authenticated.
           */
          if (auth_state == DBUS_AUTH_STATE_WAITING_FOR_INPUT ||
              auth_state == DBUS_AUTH_STATE_WAITING_FOR_MEMORY ||
              auth_state == DBUS_AUTH_STATE_AUTHENTICATED)
            need_read_watch = TRUE;
          else
            need_read_watch = FALSE;
        }
    }

  _dbus_verbose ("  setting read watch enabled = %d\n", need_read_watch);
  _dbus_connection_toggle_watch_unlocked (transport->connection,
                                          socket_transport->read_watch,
                                          need_read_watch);

  _dbus_transport_unref (transport);
}

static void
do_io_error (DBusTransport *transport)
{
  _dbus_transport_ref (transport);
  _dbus_transport_disconnect (transport);
  _dbus_transport_unref (transport);
}

/* return value is whether we successfully read any new data. */
static dbus_bool_t
read_data_into_auth (DBusTransport *transport,
                     dbus_bool_t   *oom)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  DBusString *buffer;
  int bytes_read;

  *oom = FALSE;

  _dbus_auth_get_buffer (transport->auth, &buffer);

  bytes_read = _dbus_read_socket (socket_transport->fd,
                                  buffer, socket_transport->max_bytes_read_per_iteration);

  _dbus_auth_return_buffer (transport->auth, buffer,
                            bytes_read > 0 ? bytes_read : 0);

  if (bytes_read > 0)
    {
      _dbus_verbose (" read %d bytes in auth phase\n", bytes_read);

      return TRUE;
    }
  else if (bytes_read < 0)
    {
      /* EINTR already handled for us */

      if (_dbus_get_is_errno_enomem ())
        {
          *oom = TRUE;
        }
      else if (_dbus_get_is_errno_eagain_or_ewouldblock ())
        ; /* do nothing, just return FALSE below */
      else
        {
          _dbus_verbose ("Error reading from remote app: %s\n",
                         _dbus_strerror_from_errno ());
          do_io_error (transport);
        }

      return FALSE;
    }
  else
    {
      _dbus_assert (bytes_read == 0);

      _dbus_verbose ("Disconnected from remote app\n");
      do_io_error (transport);

      return FALSE;
    }
}

/* Return value is whether we successfully wrote any bytes */
static dbus_bool_t
write_data_from_auth (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  int bytes_written;
  const DBusString *buffer;

  if (!_dbus_auth_get_bytes_to_send (transport->auth,
                                     &buffer))
    return FALSE;

  bytes_written = _dbus_write_socket (socket_transport->fd,
                                      buffer,
                                      0, _dbus_string_get_length (buffer));

  if (bytes_written > 0)
    {
      _dbus_auth_bytes_sent (transport->auth, bytes_written);
      return TRUE;
    }
  else if (bytes_written < 0)
    {
      /* EINTR already handled for us */

      if (_dbus_get_is_errno_eagain_or_ewouldblock ())
        ;
      else
        {
          _dbus_verbose ("Error writing to remote app: %s\n",
                         _dbus_strerror_from_errno ());
          do_io_error (transport);
        }
    }

  return FALSE;
}

/* FALSE on OOM */
static dbus_bool_t
exchange_credentials (DBusTransport *transport,
                      dbus_bool_t    do_reading,
                      dbus_bool_t    do_writing)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  DBusError error = DBUS_ERROR_INIT;

  _dbus_verbose ("exchange_credentials: do_reading = %d, do_writing = %d\n",
                  do_reading, do_writing);

  if (do_writing && transport->send_credentials_pending)
    {
      if (_dbus_send_credentials_socket (socket_transport->fd,
                                         &error))
        {
          transport->send_credentials_pending = FALSE;
        }
      else
        {
          _dbus_verbose ("Failed to write credentials: %s\n", error.message);
          dbus_error_free (&error);
          do_io_error (transport);
        }
    }

  if (do_reading && transport->receive_credentials_pending)
    {
      /* FIXME this can fail due to IO error _or_ OOM, broken
       * (somewhat tricky to fix since the OOM error can be set after
       * we already read the credentials byte, so basically we need to
       * separate reading the byte and storing it in the
       * transport->credentials). Does not really matter for now
       * because storing in credentials never actually fails on unix.
       */
      if (_dbus_read_credentials_socket (socket_transport->fd,
                                         transport->credentials,
                                         &error))
        {
          transport->receive_credentials_pending = FALSE;
        }
      else
        {
          _dbus_verbose ("Failed to read credentials %s\n", error.message);
          dbus_error_free (&error);
          do_io_error (transport);
        }
    }

  if (!(transport->send_credentials_pending ||
        transport->receive_credentials_pending))
    {
      if (!_dbus_auth_set_credentials (transport->auth,
                                       transport->credentials))
        return FALSE;
    }

  return TRUE;
}

static dbus_bool_t
do_authentication (DBusTransport *transport,
                   dbus_bool_t    do_reading,
                   dbus_bool_t    do_writing,
		   dbus_bool_t   *auth_completed)
{
  dbus_bool_t oom;
  dbus_bool_t orig_auth_state;

  oom = FALSE;

  orig_auth_state = _dbus_transport_get_is_authenticated (transport);

  /* This is essential to avoid the check_write_watch() at the end,
   * we don't want to add a write watch in do_iteration before
   * we try writing and get EAGAIN
   */
  if (orig_auth_state)
    {
      if (auth_completed)
        *auth_completed = FALSE;
      return TRUE;
    }

  _dbus_transport_ref (transport);

  while (!_dbus_transport_get_is_authenticated (transport) &&
         _dbus_transport_get_is_connected (transport))
    {
      if (!exchange_credentials (transport, do_reading, do_writing))
        {
          /* OOM */
          oom = TRUE;
          goto out;
        }

      if (transport->send_credentials_pending ||
          transport->receive_credentials_pending)
        {
          _dbus_verbose ("send_credentials_pending = %d receive_credentials_pending = %d\n",
                         transport->send_credentials_pending,
                         transport->receive_credentials_pending);
          goto out;
        }

#define TRANSPORT_SIDE(t) ((t)->is_server ? "server" : "client")
      switch (_dbus_auth_do_work (transport->auth))
        {
        case DBUS_AUTH_STATE_WAITING_FOR_INPUT:
          _dbus_verbose (" %s auth state: waiting for input\n",
                         TRANSPORT_SIDE (transport));
          if (!do_reading || !read_data_into_auth (transport, &oom))
            goto out;
          break;

        case DBUS_AUTH_STATE_WAITING_FOR_MEMORY:
          _dbus_verbose (" %s auth state: waiting for memory\n",
                         TRANSPORT_SIDE (transport));
          oom = TRUE;
          goto out;
          break;

        case DBUS_AUTH_STATE_HAVE_BYTES_TO_SEND:
          _dbus_verbose (" %s auth state: bytes to send\n",
                         TRANSPORT_SIDE (transport));
          if (!do_writing || !write_data_from_auth (transport))
            goto out;
          break;

        case DBUS_AUTH_STATE_NEED_DISCONNECT:
          _dbus_verbose (" %s auth state: need to disconnect\n",
                         TRANSPORT_SIDE (transport));
          do_io_error (transport);
          break;

        case DBUS_AUTH_STATE_AUTHENTICATED:
          _dbus_verbose (" %s auth state: authenticated\n",
                         TRANSPORT_SIDE (transport));
          break;
        }
    }

 out:
  if (auth_completed)
    *auth_completed = (orig_auth_state != _dbus_transport_get_is_authenticated (transport));

  check_read_watch (transport);
  check_write_watch (transport);
  _dbus_transport_unref (transport);

  if (oom)
    return FALSE;
  else
    return TRUE;
}

/* returns false on oom */
static dbus_bool_t
do_writing (DBusTransport *transport)
{
	int total;
	DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
	dbus_bool_t oom;

	/* No messages without authentication! */
	if (!_dbus_transport_get_is_authenticated (transport))
    {
		_dbus_verbose ("Not authenticated, not writing anything\n");
		return TRUE;
    }

	if (transport->disconnected)
    {
		_dbus_verbose ("Not connected, not writing anything\n");
		return TRUE;
    }

#if 1
	_dbus_verbose ("do_writing(), have_messages = %d, fd = %d\n",
                 _dbus_connection_has_messages_to_send_unlocked (transport->connection),
                 socket_transport->fd);
#endif

	oom = FALSE;
	total = 0;

	while (!transport->disconnected && _dbus_connection_has_messages_to_send_unlocked (transport->connection))
    {
		int bytes_written;
		DBusMessage *message;
		const DBusString *header;
		const DBusString *body;
		int total_bytes_to_write;


		if (total > socket_transport->max_bytes_written_per_iteration)
        {
			_dbus_verbose ("%d bytes exceeds %d bytes written per iteration, returning\n",
                         total, socket_transport->max_bytes_written_per_iteration);
			goto out;
        }

		message = _dbus_connection_get_message_to_send (transport->connection);
		_dbus_assert (message != NULL);
		dbus_message_lock (message);
		_dbus_message_get_network_data (message, &header, &body);

		if (_dbus_auth_needs_encoding (transport->auth))
        {
			// Does fd passing even make sense with encoded data?
			_dbus_assert(!DBUS_TRANSPORT_CAN_SEND_UNIX_FD(transport));

			if (_dbus_string_get_length (&socket_transport->encoded_outgoing) == 0)
            {
				if (!_dbus_auth_encode_data (transport->auth,
                                           header, &socket_transport->encoded_outgoing))
                {
					oom = TRUE;
					goto out;
                }

				if (!_dbus_auth_encode_data (transport->auth,
                                           body, &socket_transport->encoded_outgoing))
                {
					_dbus_string_set_length (&socket_transport->encoded_outgoing, 0);
					oom = TRUE;
					goto out;
                }
            }

			total_bytes_to_write = _dbus_string_get_length (&socket_transport->encoded_outgoing);
			bytes_written = kdbus_write_msg_encoded(message, socket_transport);
        }
		else
		{
			total_bytes_to_write = _dbus_string_get_length(header) + _dbus_string_get_length(body);
			bytes_written = kdbus_write_msg(transport->connection, message, socket_transport->fd);
		}

		if (bytes_written < 0)
		{
			/* EINTR already handled for us */

          /* For some discussion of why we also ignore EPIPE here, see
           * http://lists.freedesktop.org/archives/dbus/2008-March/009526.html
           */

			if (_dbus_get_is_errno_eagain_or_ewouldblock () || _dbus_get_is_errno_epipe ())
				goto out;
			else
			{
				_dbus_verbose ("Error writing to remote app: %s\n",
							 _dbus_strerror_from_errno ());
				do_io_error (transport);
				goto out;
			}
		}
		else
		{
			_dbus_verbose (" wrote %d bytes of %d\n", bytes_written,
                         total_bytes_to_write);

			total += bytes_written;
			socket_transport->message_bytes_written += bytes_written;

			_dbus_assert (socket_transport->message_bytes_written <=
                        total_bytes_to_write);

			  if (socket_transport->message_bytes_written == total_bytes_to_write)
			  {
				  socket_transport->message_bytes_written = 0;
				  _dbus_string_set_length (&socket_transport->encoded_outgoing, 0);
				  _dbus_string_compact (&socket_transport->encoded_outgoing, 2048);

				  _dbus_connection_message_sent_unlocked (transport->connection,
														  message);
			  }
		}
    }

	out:
	if (oom)
		return FALSE;
	else
		return TRUE;
}

/* returns false on out-of-memory */
static dbus_bool_t
do_reading (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  DBusString *buffer;
  int bytes_read;
  int total;
  dbus_bool_t oom;

  _dbus_verbose ("fd = %d\n",socket_transport->fd);

  /* No messages without authentication! */
  if (!_dbus_transport_get_is_authenticated (transport))
    return TRUE;

  oom = FALSE;

  total = 0;

 again:

  /* See if we've exceeded max messages and need to disable reading */
  check_read_watch (transport);

  if (total > socket_transport->max_bytes_read_per_iteration)
    {
      _dbus_verbose ("%d bytes exceeds %d bytes read per iteration, returning\n",
                     total, socket_transport->max_bytes_read_per_iteration);
      goto out;
    }

  _dbus_assert (socket_transport->read_watch != NULL ||
                transport->disconnected);

  if (transport->disconnected)
    goto out;

  if (!dbus_watch_get_enabled (socket_transport->read_watch))
    return TRUE;

  if (_dbus_auth_needs_decoding (transport->auth))  //todo
    {
      /* Does fd passing even make sense with encoded data? */
      _dbus_assert(!DBUS_TRANSPORT_CAN_SEND_UNIX_FD(transport));

      if (_dbus_string_get_length (&socket_transport->encoded_incoming) > 0)
        bytes_read = _dbus_string_get_length (&socket_transport->encoded_incoming);
      else
        bytes_read = _dbus_read_socket (socket_transport->fd,
                                        &socket_transport->encoded_incoming,
                                        socket_transport->max_bytes_read_per_iteration);

      _dbus_assert (_dbus_string_get_length (&socket_transport->encoded_incoming) ==
                    bytes_read);

      if (bytes_read > 0)
        {
          int orig_len;

          _dbus_message_loader_get_buffer (transport->loader,
                                           &buffer);

          orig_len = _dbus_string_get_length (buffer);

          if (!_dbus_auth_decode_data (transport->auth,
                                       &socket_transport->encoded_incoming,
                                       buffer))
            {
              _dbus_verbose ("Out of memory decoding incoming data\n");
              _dbus_message_loader_return_buffer (transport->loader,
                                              buffer,
                                              _dbus_string_get_length (buffer) - orig_len);

              oom = TRUE;
              goto out;
            }

          _dbus_message_loader_return_buffer (transport->loader,
                                              buffer,
                                              _dbus_string_get_length (buffer) - orig_len);

          _dbus_string_set_length (&socket_transport->encoded_incoming, 0);
          _dbus_string_compact (&socket_transport->encoded_incoming, 2048);
        }
    }
  else
    {
      _dbus_message_loader_get_buffer (transport->loader,
                                       &buffer);

      bytes_read = kdbus_read_message(socket_transport, buffer);

      _dbus_message_loader_return_buffer (transport->loader,
                                          buffer,
                                          bytes_read < 0 ? 0 : bytes_read);
    }

  if (bytes_read < 0)
    {
      /* EINTR already handled for us */

      if (_dbus_get_is_errno_enomem ())
        {
          _dbus_verbose ("Out of memory in read()/do_reading()\n");
          oom = TRUE;
          goto out;
        }
      else if (_dbus_get_is_errno_eagain_or_ewouldblock ())
        goto out;
      else
        {
          _dbus_verbose ("Error reading from remote app: %s\n",
                         _dbus_strerror_from_errno ());
          do_io_error (transport);
          goto out;
        }
    }
  else if (bytes_read == 0)
    {
      _dbus_verbose ("Disconnected from remote app\n");
//      do_io_error (transport);  todo temporarily commented out for tests
      goto out;
    }
  else
    {
      _dbus_verbose (" read %d bytes\n", bytes_read);

      total += bytes_read;

      if (!_dbus_transport_queue_messages (transport))
        {
          oom = TRUE;
          _dbus_verbose (" out of memory when queueing messages we just read in the transport\n");
          goto out;
        }

      /* Try reading more data until we get EAGAIN and return, or
       * exceed max bytes per iteration.  If in blocking mode of
       * course we'll block instead of returning.
       */
      goto again;
    }

 out:
  if (oom)
    return FALSE;
  else
    return TRUE;
}

static dbus_bool_t
unix_error_with_read_to_come (DBusTransport *itransport,
                              DBusWatch     *watch,
                              unsigned int   flags)
{
  DBusTransportSocket *transport = (DBusTransportSocket *) itransport;

  if (!(flags & DBUS_WATCH_HANGUP || flags & DBUS_WATCH_ERROR))
    return FALSE;

  /* If we have a read watch enabled ...
     we -might have data incoming ... => handle the HANGUP there */
  if (watch != transport->read_watch &&
      _dbus_watch_get_enabled (transport->read_watch))
    return FALSE;

  return TRUE;
}

static dbus_bool_t
socket_handle_watch (DBusTransport *transport,
                   DBusWatch     *watch,
                   unsigned int   flags)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  _dbus_assert (watch == socket_transport->read_watch ||
                watch == socket_transport->write_watch);
  _dbus_assert (watch != NULL);

  /* If we hit an error here on a write watch, don't disconnect the transport yet because data can
   * still be in the buffer and do_reading may need several iteration to read
   * it all (because of its max_bytes_read_per_iteration limit).
   */
  if (!(flags & DBUS_WATCH_READABLE) && unix_error_with_read_to_come (transport, watch, flags))
    {
      _dbus_verbose ("Hang up or error on watch\n");
      _dbus_transport_disconnect (transport);
      return TRUE;
    }

  if (watch == socket_transport->read_watch &&
      (flags & DBUS_WATCH_READABLE))
    {
      dbus_bool_t auth_finished;
#if 1
      _dbus_verbose ("handling read watch %p flags = %x\n",
                     watch, flags);
#endif
      if (!do_authentication (transport, TRUE, FALSE, &auth_finished))
        return FALSE;

      /* We don't want to do a read immediately following
       * a successful authentication.  This is so we
       * have a chance to propagate the authentication
       * state further up.  Specifically, we need to
       * process any pending data from the auth object.
       */
      if (!auth_finished)
	{
	  if (!do_reading (transport))
	    {
	      _dbus_verbose ("no memory to read\n");
	      return FALSE;
	    }
	}
      else
        {
          _dbus_verbose ("Not reading anything since we just completed the authentication\n");
        }
    }
  else if (watch == socket_transport->write_watch &&
           (flags & DBUS_WATCH_WRITABLE))
    {
#if 1
      _dbus_verbose ("handling write watch, have_outgoing_messages = %d\n",
                     _dbus_connection_has_messages_to_send_unlocked (transport->connection));
#endif
      if (!do_authentication (transport, FALSE, TRUE, NULL))
        return FALSE;

      if (!do_writing (transport))
        {
          _dbus_verbose ("no memory to write\n");
          return FALSE;
        }

      /* See if we still need the write watch */
      check_write_watch (transport);
    }
#ifdef DBUS_ENABLE_VERBOSE_MODE
  else
    {
      if (watch == socket_transport->read_watch)
        _dbus_verbose ("asked to handle read watch with non-read condition 0x%x\n",
                       flags);
      else if (watch == socket_transport->write_watch)
        _dbus_verbose ("asked to handle write watch with non-write condition 0x%x\n",
                       flags);
      else
        _dbus_verbose ("asked to handle watch %p on fd %d that we don't recognize\n",
                       watch, dbus_watch_get_socket (watch));
    }
#endif /* DBUS_ENABLE_VERBOSE_MODE */

  return TRUE;
}

static void
socket_disconnect (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  _dbus_verbose ("\n");

  free_watches (transport);

  _dbus_close_socket (socket_transport->fd, NULL);
  socket_transport->fd = -1;
}

static dbus_bool_t
socket_connection_set (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  _dbus_watch_set_handler (socket_transport->write_watch,
                           _dbus_connection_handle_watch,
                           transport->connection, NULL);

  _dbus_watch_set_handler (socket_transport->read_watch,
                           _dbus_connection_handle_watch,
                           transport->connection, NULL);

  if (!_dbus_connection_add_watch_unlocked (transport->connection,
                                            socket_transport->write_watch))
    return FALSE;

  if (!_dbus_connection_add_watch_unlocked (transport->connection,
                                            socket_transport->read_watch))
    {
      _dbus_connection_remove_watch_unlocked (transport->connection,
                                              socket_transport->write_watch);
      return FALSE;
    }

  check_read_watch (transport);
  check_write_watch (transport);

  return TRUE;
}

/**
 * @todo We need to have a way to wake up the select sleep if
 * a new iteration request comes in with a flag (read/write) that
 * we're not currently serving. Otherwise a call that just reads
 * could block a write call forever (if there are no incoming
 * messages).
 */
static  void
kdbus_do_iteration (DBusTransport *transport,
                   unsigned int   flags,
                   int            timeout_milliseconds)
{
	DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
	DBusPollFD poll_fd;
	int poll_res;
	int poll_timeout;

	_dbus_verbose (" iteration flags = %s%s timeout = %d read_watch = %p write_watch = %p fd = %d\n",
                 flags & DBUS_ITERATION_DO_READING ? "read" : "",
                 flags & DBUS_ITERATION_DO_WRITING ? "write" : "",
                 timeout_milliseconds,
                 socket_transport->read_watch,
                 socket_transport->write_watch,
                 socket_transport->fd);

  /* the passed in DO_READING/DO_WRITING flags indicate whether to
   * read/write messages, but regardless of those we may need to block
   * for reading/writing to do auth.  But if we do reading for auth,
   * we don't want to read any messages yet if not given DO_READING.
   */

  poll_fd.fd = socket_transport->fd;
  poll_fd.events = 0;

  if (_dbus_transport_get_is_authenticated (transport))
    {
      /* This is kind of a hack; if we have stuff to write, then try
       * to avoid the poll. This is probably about a 5% speedup on an
       * echo client/server.
       *
       * If both reading and writing were requested, we want to avoid this
       * since it could have funky effects:
       *   - both ends spinning waiting for the other one to read
       *     data so they can finish writing
       *   - prioritizing all writing ahead of reading
       */
      if ((flags & DBUS_ITERATION_DO_WRITING) &&
          !(flags & (DBUS_ITERATION_DO_READING | DBUS_ITERATION_BLOCK)) &&
          !transport->disconnected &&
          _dbus_connection_has_messages_to_send_unlocked (transport->connection))
        {
          do_writing (transport);

          if (transport->disconnected ||
              !_dbus_connection_has_messages_to_send_unlocked (transport->connection))
            goto out;
        }

      /* If we get here, we decided to do the poll() after all */
      _dbus_assert (socket_transport->read_watch);
      if (flags & DBUS_ITERATION_DO_READING)
	poll_fd.events |= _DBUS_POLLIN;

      _dbus_assert (socket_transport->write_watch);
      if (flags & DBUS_ITERATION_DO_WRITING)
        poll_fd.events |= _DBUS_POLLOUT;
    }
  else
    {
      DBusAuthState auth_state;

      auth_state = _dbus_auth_do_work (transport->auth);

      if (transport->receive_credentials_pending ||
          auth_state == DBUS_AUTH_STATE_WAITING_FOR_INPUT)
	poll_fd.events |= _DBUS_POLLIN;

      if (transport->send_credentials_pending ||
          auth_state == DBUS_AUTH_STATE_HAVE_BYTES_TO_SEND)
	poll_fd.events |= _DBUS_POLLOUT;
    }

  if (poll_fd.events)
    {
      if (flags & DBUS_ITERATION_BLOCK)
	poll_timeout = timeout_milliseconds;
      else
	poll_timeout = 0;

      /* For blocking selects we drop the connection lock here
       * to avoid blocking out connection access during a potentially
       * indefinite blocking call. The io path is still protected
       * by the io_path_cond condvar, so we won't reenter this.
       */
      if (flags & DBUS_ITERATION_BLOCK)
        {
          _dbus_verbose ("unlock pre poll\n");
          _dbus_connection_unlock (transport->connection);
        }
      _dbus_verbose ("poll_fd.events: %x, timeout: %d\n", poll_fd.events, poll_timeout);
    again:
      poll_res = _dbus_poll (&poll_fd, 1, poll_timeout);

      if (poll_res < 0 && _dbus_get_is_errno_eintr ())
      {
          _dbus_verbose ("Error from _dbus_poll(): %s\n",
                         _dbus_strerror_from_errno ());
    	  goto again;
      }
      _dbus_verbose ("poll_fd.revents: %x\n", poll_fd.revents);

    /*  poll_res = poll_timeout;			// todo temporary walkaround of above problem
      poll_res = 1;							// todo temporary walkaround of above problem
      poll_fd.revents = poll_fd.events;    // todo temporary walkaround of above problem*/

      if (flags & DBUS_ITERATION_BLOCK)
        {
          _dbus_verbose ("lock post poll\n");
          _dbus_connection_lock (transport->connection);
        }

      if (poll_res >= 0)
        {
          if (poll_res == 0)
            poll_fd.revents = 0; /* some concern that posix does not guarantee this;
                                  * valgrind flags it as an error. though it probably
                                  * is guaranteed on linux at least.
                                  */

          if (poll_fd.revents & _DBUS_POLLERR)
            do_io_error (transport);
          else
            {
              dbus_bool_t need_read = (poll_fd.revents & _DBUS_POLLIN) > 0;
              dbus_bool_t need_write = (poll_fd.revents & _DBUS_POLLOUT) > 0;
	      dbus_bool_t authentication_completed;

              _dbus_verbose ("in iteration, need_read=%d need_write=%d\n",
                             need_read, need_write);
              do_authentication (transport, need_read, need_write,
				 &authentication_completed);

	      /* See comment in socket_handle_watch. */
	      if (authentication_completed)
                goto out;

              if (need_read && (flags & DBUS_ITERATION_DO_READING))
                do_reading (transport);
              if (need_write && (flags & DBUS_ITERATION_DO_WRITING))
                do_writing (transport);
            }
        }
      else
        {
          _dbus_verbose ("Error from _dbus_poll(): %s\n",
                         _dbus_strerror_from_errno ());
        }
    }


 out:
  /* We need to install the write watch only if we did not
   * successfully write everything. Note we need to be careful that we
   * don't call check_write_watch *before* do_writing, since it's
   * inefficient to add the write watch, and we can avoid it most of
   * the time since we can write immediately.
   *
   * However, we MUST always call check_write_watch(); DBusConnection code
   * relies on the fact that running an iteration will notice that
   * messages are pending.
   */
  check_write_watch (transport);

  _dbus_verbose (" ... leaving do_iteration()\n");
}

static void
socket_live_messages_changed (DBusTransport *transport)
{
  /* See if we should look for incoming messages again */
  check_read_watch (transport);
}

static const DBusTransportVTable kdbus_vtable = {
  socket_finalize,
  socket_handle_watch,
  socket_disconnect,
  socket_connection_set,
  kdbus_do_iteration,
  socket_live_messages_changed,
  socket_get_socket_fd
};

/**
 * Creates a new transport for the given kdbus file descriptor.  The file
 * descriptor must be nonblocking (use _dbus_set_fd_nonblocking() to
 * make it so).
 *
 * @param fd the file descriptor.
 * @param server_guid non-#NULL if this transport is on the server side of a connection
 * @param address the transport's address
 * @returns the new transport, or #NULL if no memory.
 */
DBusTransport*
_dbus_transport_new_for_socket_kdbus (int	fd,
                                	  const DBusString *server_guid,
                                	  const DBusString *address)
{
	DBusTransportSocket *socket_transport;

  socket_transport = dbus_new0 (DBusTransportSocket, 1);
  if (socket_transport == NULL)
    return NULL;

  if (!_dbus_string_init (&socket_transport->encoded_outgoing))
    goto failed_0;

  if (!_dbus_string_init (&socket_transport->encoded_incoming))
    goto failed_1;

  socket_transport->write_watch = _dbus_watch_new (fd,
                                                 DBUS_WATCH_WRITABLE,
                                                 FALSE,
                                                 NULL, NULL, NULL);
  if (socket_transport->write_watch == NULL)
    goto failed_2;

  socket_transport->read_watch = _dbus_watch_new (fd,
                                                DBUS_WATCH_READABLE,
                                                FALSE,
                                                NULL, NULL, NULL);
  if (socket_transport->read_watch == NULL)
    goto failed_3;

  if (!_dbus_transport_init_base (&socket_transport->base,
                                  &kdbus_vtable,
                                  server_guid, address))
    goto failed_4;

#ifdef HAVE_UNIX_FD_PASSING
  _dbus_auth_set_unix_fd_possible(socket_transport->base.auth, _dbus_socket_can_pass_unix_fd(fd));
#endif

  socket_transport->fd = fd;
  socket_transport->message_bytes_written = 0;

  /* These values should probably be tunable or something. */
  socket_transport->max_bytes_read_per_iteration = POOL_SIZE;
  socket_transport->max_bytes_written_per_iteration = 2048;

  socket_transport->kdbus_mmap_ptr = NULL;

  return (DBusTransport*) socket_transport;

 failed_4:
  _dbus_watch_invalidate (socket_transport->read_watch);
  _dbus_watch_unref (socket_transport->read_watch);
 failed_3:
  _dbus_watch_invalidate (socket_transport->write_watch);
  _dbus_watch_unref (socket_transport->write_watch);
 failed_2:
  _dbus_string_free (&socket_transport->encoded_incoming);
 failed_1:
  _dbus_string_free (&socket_transport->encoded_outgoing);
 failed_0:
  dbus_free (socket_transport);
  return NULL;
}


/**
 * Creates a connection to the kdbus bus
  *
 * This will set FD_CLOEXEC for the socket returned.
 *
 * @param path the path to UNIX domain socket
 * @param error return location for error code
 * @returns connection file descriptor or -1 on error
 */
int _dbus_connect_kdbus (const char *path, DBusError *error)
{
	int fd;

	_DBUS_ASSERT_ERROR_IS_CLEAR (error);
	_dbus_verbose ("connecting to kdbus bus %s\n", path);

	fd = open(path, O_RDWR|O_CLOEXEC|O_NONBLOCK); //[RP] | O_NONBLOCK added here, in dbus added separately in section commented out below
	if (fd < 0)
	{
		dbus_set_error(error, _dbus_error_from_errno (errno), "Failed to open file descriptor: %s", _dbus_strerror (errno));
		_DBUS_ASSERT_ERROR_IS_SET(error);
		return -1;  //[RP] not needed here if commented block below is removed
	}

	/*if (!_dbus_set_fd_nonblocking (fd, error))
    {
		_DBUS_ASSERT_ERROR_IS_SET (error);
		_dbus_close (fd, NULL);
		return -1;
    }*/

	return fd;
}

dbus_bool_t kdbus_mmap(DBusTransport* transport)
{
	DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

	socket_transport->kdbus_mmap_ptr = mmap(NULL, POOL_SIZE, PROT_READ, MAP_SHARED, socket_transport->fd, 0);
	if (socket_transport->kdbus_mmap_ptr == MAP_FAILED)
		return FALSE;

	return TRUE;
}

/**
 * Creates a new transport for kdbus.
 * This creates a client-side of a transport.
 *
 * @param path the path to the domain socket.
 * @param error address where an error can be returned.
 * @returns a new transport, or #NULL on failure.
 */
DBusTransport* _dbus_transport_new_for_kdbus (const char *path, DBusError *error)
{
	int fd;
	DBusTransport *transport;
	DBusString address;

	_DBUS_ASSERT_ERROR_IS_CLEAR (error);

	if (!_dbus_string_init (&address))
    {
		dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
		return NULL;
    }

	fd = -1;

	if ((!_dbus_string_append (&address, "kdbus:path=")) || (!_dbus_string_append (&address, path)))
    {
		dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
		goto failed_0;
    }

	fd = _dbus_connect_kdbus (path, error);
	if (fd < 0)
    {
		_DBUS_ASSERT_ERROR_IS_SET (error);
		goto failed_0;
    }

	_dbus_verbose ("Successfully connected to kdbus bus %s\n", path);

	transport = _dbus_transport_new_for_socket_kdbus (fd, NULL, &address);
	if (transport == NULL)
    {
		dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
		goto failed_1;
    }

	_dbus_string_free (&address);

	return transport;

	failed_1:
		_dbus_close_socket (fd, NULL);
  	failed_0:
  		_dbus_string_free (&address);
  	return NULL;
}


/**
 * Opens kdbus transport.
 *
 * @param entry the address entry to try opening
 * @param transport_p return location for the opened transport
 * @param error error to be set
 * @returns result of the attempt
 */
DBusTransportOpenResult _dbus_transport_open_kdbus(DBusAddressEntry  *entry,
                                        		   DBusTransport    **transport_p,
                                        		   DBusError         *error)
{
	const char *method;

	method = dbus_address_entry_get_method (entry);
	_dbus_assert (method != NULL);

	if (strcmp (method, "kdbus") == 0)
    {
		const char *path = dbus_address_entry_get_value (entry, "path");

		if (path == NULL)
        {
			_dbus_set_bad_address (error, "kdbus", "path", NULL);
			return DBUS_TRANSPORT_OPEN_BAD_ADDRESS;
        }

        *transport_p = _dbus_transport_new_for_kdbus (path, error);

        if (*transport_p == NULL)
        {
        	_DBUS_ASSERT_ERROR_IS_SET (error);
        	return DBUS_TRANSPORT_OPEN_DID_NOT_CONNECT;
        }
        else
        {
        	_DBUS_ASSERT_ERROR_IS_CLEAR (error);
        	return DBUS_TRANSPORT_OPEN_OK;
        }
    }
	else
    {
		_DBUS_ASSERT_ERROR_IS_CLEAR (error);
		return DBUS_TRANSPORT_OPEN_NOT_HANDLED;
    }
}

struct kdbus_policy *make_policy_name(const char *name)
{
	struct kdbus_policy *p;
	__u64 size;

	size = offsetof(struct kdbus_policy, name) + strlen(name) + 1;
	p = malloc(size);
	if (!p)
		return NULL;
	memset(p, 0, size);
	p->size = size;
	p->type = KDBUS_POLICY_NAME;
	strcpy(p->name, name);

	return p;
}

struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id)
{
	struct kdbus_policy *p;
	__u64 size = sizeof(*p);

	p = malloc(size);
	if (!p)
		return NULL;

	memset(p, 0, size);
	p->size = size;
	p->type = KDBUS_POLICY_ACCESS;
	p->access.type = type;
	p->access.bits = bits;
	p->access.id = id;

	return p;
}

void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size)
{
	struct kdbus_policy *dst = (struct kdbus_policy *) ((char *) cmd_policy + cmd_policy->size);

	if (cmd_policy->size + policy->size > max_size)
		return;

	memcpy(dst, policy, policy->size);
	cmd_policy->size += KDBUS_ALIGN8(policy->size);
	free(policy);
}

dbus_bool_t bus_register_policy_kdbus(const char* name, DBusConnection *connection, DBusError *error)
{
	struct kdbus_cmd_policy *cmd_policy;
	struct kdbus_policy *policy;
	int size = 0xffff;
	int fd;

	if(!dbus_connection_get_socket(connection, &fd))
	{
		dbus_set_error (error, "Failed to get fd for registering policy", NULL);
		return FALSE;
	}

	cmd_policy = (struct kdbus_cmd_policy *) alloca(size);
	memset(cmd_policy, 0, size);

	policy = (struct kdbus_policy *) cmd_policy->policies;
	cmd_policy->size = offsetof(struct kdbus_cmd_policy, policies);

	policy = make_policy_name(name);    		//todo to be verified or changed when meaning will be known
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_USER, KDBUS_POLICY_OWN, getuid());
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_RECV, 0);
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_SEND, 0);
	append_policy(cmd_policy, policy, size);

	if (ioctl(fd, KDBUS_CMD_EP_POLICY_SET, cmd_policy) < 0)
	{
		dbus_set_error(error,_dbus_error_from_errno (errno), "Error setting EP policy: %s", _dbus_strerror (errno));
		return FALSE;
	}

	_dbus_verbose("Policy %s set correctly\n", name);
	return TRUE;
}

dbus_bool_t bus_register_kdbus(char* name, DBusConnection *connection, DBusError *error)
{
	struct kdbus_cmd_hello hello;
	int fd;

	memset(&hello, 0, sizeof(hello));
	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD |
			   KDBUS_HELLO_ATTACH_COMM |
			   KDBUS_HELLO_ATTACH_EXE |
			   KDBUS_HELLO_ATTACH_CMDLINE |
			   KDBUS_HELLO_ATTACH_CAPS |
			   KDBUS_HELLO_ATTACH_CGROUP |
			   KDBUS_HELLO_ATTACH_SECLABEL |
			   KDBUS_HELLO_ATTACH_AUDIT;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = POOL_SIZE;

	if(!dbus_connection_get_socket(connection, &fd))
	{
		dbus_set_error (error, "failed to get fd for bus registration", NULL);
		return FALSE;
	}
	if (ioctl(fd, KDBUS_CMD_HELLO, &hello))
	{
		dbus_set_error(error,_dbus_error_from_errno (errno), "Failed to send hello: %s", _dbus_strerror (errno));
		return FALSE;
	}

	_dbus_verbose("-- Our peer ID is: %llu\n", (unsigned long long)hello.id);
	sprintf(name, "%llu", (unsigned long long)hello.id);

	if(!kdbus_mmap(dbus_connection_get_transport(connection)))
	{
		dbus_set_error(error,_dbus_error_from_errno (errno), "Error when mmap: %s", _dbus_strerror (errno));
		return FALSE;
	}

	return TRUE;
}

uint64_t bus_request_name_kdbus(DBusConnection *connection, const char *name, const uint64_t flags, DBusError *error)
{
	struct kdbus_cmd_name *cmd_name;
	int fd;
	uint64_t size = sizeof(*cmd_name) + strlen(name) + 1;
	uint64_t flags_kdbus = 0;

	cmd_name = alloca(size);

	memset(cmd_name, 0, size);
	strcpy(cmd_name->name, name);
	cmd_name->size = size;

	if(flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)
		flags_kdbus |= KDBUS_NAME_ALLOW_REPLACEMENT;
	if(!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE))
		flags_kdbus |= KDBUS_NAME_QUEUE;
	if(flags & DBUS_NAME_FLAG_REPLACE_EXISTING)
		flags_kdbus |= KDBUS_NAME_REPLACE_EXISTING;

	cmd_name->conn_flags = flags_kdbus;

	if(!dbus_connection_get_socket(connection, &fd))
	{
		dbus_set_error (error, "failed to get fd for name request", NULL);
		return FALSE;
	}

	_dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->conn_flags);

	_DBUS_ASSERT_ERROR_IS_CLEAR (error);
	if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name))
	{
		dbus_set_error(error,_dbus_error_from_errno (errno), "error acquiring name: %s", _dbus_strerror (errno));
		if(errno == EEXIST)
			return DBUS_REQUEST_NAME_REPLY_EXISTS;
		return FALSE;
	}

	_dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->conn_flags);

	if(cmd_name->conn_flags & KDBUS_NAME_IN_QUEUE)
		return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
	else
		return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
	//todo now 1 codes are never returned -  DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
}

/**
 * Checks if the connection's transport is kdbus on the basis of its address
 *
 * @param pointer to the connection
 * @returns TRUE if kdbus transport, otherwise FALSE
 */
dbus_bool_t dbus_transport_is_kdbus(DBusConnection *connection)
{
	const char* address = _dbus_connection_get_address(connection);

	//todo maybe assert here if address == NULL
	if(address == strstr(address, "kdbus:path="))
		return TRUE;
	else
		return FALSE;
}

void dbus_bus_add_match_kdbus (DBusConnection *connection, const char *rule, DBusError *error)
{
	struct kdbus_cmd_match cmd_match;
	int fd;

	memset(&cmd_match, 0, sizeof(cmd_match));

	if(!dbus_connection_get_socket(connection, &fd))
	{
		dbus_set_error (error, "failed to get fd for add match", NULL);
		return;
	}

	cmd_match.size = sizeof(cmd_match);

	//todo add matching rules from *rule when it will be docuemnted in kdbus


	cmd_match.src_id = KDBUS_MATCH_SRC_ID_ANY;

	if (ioctl(fd, KDBUS_CMD_MATCH_ADD, &cmd_match))
		dbus_set_error(error,_dbus_error_from_errno (errno), "error adding match: %s", _dbus_strerror (errno));

	_dbus_verbose("Finished adding match bus rule %s             !!!!!!!!!\n", rule);
}
