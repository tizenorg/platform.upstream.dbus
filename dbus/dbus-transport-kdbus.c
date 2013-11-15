/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-transport-kdbus.c  kdbus subclasses of DBusTransport
 *
 * Copyright (C) 2002, 2003, 2004, 2006  Red Hat Inc
 * Copyright (C) 2013  Samsung Electronics
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version and under the terms of the GNU
 * Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include "dbus-transport.h"
#include "dbus-transport-kdbus.h"
#include "dbus-transport-protected.h"
#include "dbus-connection-internal.h"
#include "kdbus.h"
#include "dbus-watch.h"
#include "dbus-errors.h"
#include "dbus-bus.h"
#include "kdbus-common.h"
#include <linux/types.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <limits.h>
#include <sys/stat.h>

#define KDBUS_PART_FOREACH(part, head, first)				\
	for (part = (head)->first;					\
	     (uint8_t *)(part) < (uint8_t *)(head) + (head)->size;	\
	     part = KDBUS_PART_NEXT(part))
#define RECEIVE_POOL_SIZE (10 * 1024LU * 1024LU)
#define MEMFD_SIZE_THRESHOLD (2 * 1024 * 1024LU) // over this memfd is used
//todo add compilation-time check if MEMFD_SIZE_THERSHOLD is lower than max payload vector size defined in kdbus.h

#define KDBUS_MSG_DECODE_DEBUG 0

#define ITER_APPEND_STR(string) \
if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &string))   \
{ \
	ret_size = -1;  \
	goto out;  \
}\

#define MSG_ITEM_BUILD_VEC(data, datasize)                                    \
	item->type = KDBUS_MSG_PAYLOAD_VEC;					\
        item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_vec);		\
        item->vec.address = (unsigned long) data;       			\
        item->vec.size = datasize;

/**
 * Opaque object representing a transport. In kdbus transport it has nothing common
 * with socket, but the name was preserved to comply with  upper functions.
 */
typedef struct DBusTransportKdbus DBusTransportKdbus;

/**
 * Implementation details of DBusTransportSocket. All members are private.
 */
struct DBusTransportKdbus
{
  DBusTransport base;                   /**< Parent instance */
  int fd;                               /**< File descriptor. */
  DBusWatch *read_watch;                /**< Watch for readability. */
  DBusWatch *write_watch;               /**< Watch for writability. */

  int max_bytes_read_per_iteration;     /**< In kdbus only to control overall message size*/
  int max_bytes_written_per_iteration;  /**< In kdbus only to control overall message size*/

  int message_bytes_written;            /**< Number of bytes of current
                                         *   outgoing message that have
                                         *   been written.
                                         */
  void* kdbus_mmap_ptr;	                /**< Mapped memory where Kdbus (kernel) writes
                                         *   messages incoming to us.
                                         */
  int memfd;                            /**< File descriptor to special 
                                         *   memory pool for bulk data
                                         *   transfer. Retrieved from 
                                         *   Kdbus kernel module. 
                                         */
  __u64 bloom_size;						/**<  bloom filter field size */
  char* sender;                         /**< uniqe name of the sender */
};

__u64 dbus_transport_get_bloom_size(DBusTransport* transport)
{
  return ((DBusTransportKdbus*)transport)->bloom_size;
}

/*
 * Adds locally generated message to received messages queue
 *
 */
static dbus_bool_t add_message_to_received(DBusMessage *message, DBusConnection* connection)
{
	DBusList *message_link;

	message_link = _dbus_list_alloc_link (message);
	if (message_link == NULL)
	{
		dbus_message_unref (message);
		return FALSE;
	}

	_dbus_connection_queue_synthesized_message_link(connection, message_link);

	return TRUE;
}

/*
 * Generates local error message as a reply to message given as parameter
 * and adds generated error message to received messages queue.
 */
static int reply_with_error(char* error_type, const char* template, const char* object, DBusMessage *message, DBusConnection* connection)
{
	DBusMessage *errMessage;
	char* error_msg = "";

	if(template)
	{
		error_msg = alloca(strlen(template) + strlen(object));
		sprintf(error_msg, template, object);
	}
	else if(object)
		error_msg = (char*)object;

	errMessage = generate_local_error_message(dbus_message_get_serial(message), error_type, error_msg);
	if(errMessage == NULL)
		return -1;
	if (add_message_to_received(errMessage, connection))
		return 0;

	return -1;
}

/*
 *  Generates reply to the message given as a parameter with one item in the reply body
 *  and adds generated reply message to received messages queue.
 */
static int reply_1_data(DBusMessage *message, int data_type, void* pData, DBusConnection* connection)
{
	DBusMessageIter args;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if(reply == NULL)
		return -1;
	dbus_message_set_sender(reply, DBUS_SERVICE_DBUS);
    dbus_message_iter_init_append(reply, &args);
    if (!dbus_message_iter_append_basic(&args, data_type, pData))
    {
    	dbus_message_unref(reply);
        return -1;
    }
    if(add_message_to_received(reply, connection))
    	return 0;

    return -1;
}

/*
static int reply_ack(DBusMessage *message, DBusConnection* connection)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if(reply == NULL)
		return -1;
    if(add_message_to_received(reply, connection))
    	return 0;
    return -1;
}*/

/**
 * Retrieves file descriptor to memory pool from kdbus module.
 * It is then used for bulk data sending.
 * Triggered when message payload is over MEMFD_SIZE_THRESHOLD
 * 
 */
static int kdbus_init_memfd(DBusTransportKdbus* socket_transport)
{
	int memfd;
	
		if (ioctl(socket_transport->fd, KDBUS_CMD_MEMFD_NEW, &memfd) < 0) {
			_dbus_verbose("KDBUS_CMD_MEMFD_NEW failed: \n");
			return -1;
		}

		socket_transport->memfd = memfd;
		_dbus_verbose("kdbus_init_memfd: %d!!\n", socket_transport->memfd);
	return 0;
}

/**
 * Initiates Kdbus message structure. 
 * Calculates it's size, allocates memory and fills some fields.
 * @param name Well-known name or NULL
 * @param dst_id Numeric id of recipient
 * @param body_size size of message body if present
 * @param use_memfd flag to build memfd message
 * @param fds_count number of file descriptors used
 * @param transport transport
 * @return initialized kdbus message
 */
static struct kdbus_msg* kdbus_init_msg(const char* name, __u64 dst_id, uint64_t body_size, dbus_bool_t use_memfd, int fds_count, DBusTransportKdbus *transport)
{
    struct kdbus_msg* msg;
    uint64_t msg_size;

    msg_size = sizeof(struct kdbus_msg);

    if(use_memfd == TRUE)  // bulk data - memfd
        msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
    else
      {
        msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));  //header is a must
        while(body_size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
          {
            msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
            body_size -= KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
          }
        if(body_size)
          msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
      }

    if(fds_count)
    	msg_size += KDBUS_ITEM_SIZE(sizeof(int)*fds_count);

    if (name)
    	msg_size += KDBUS_ITEM_SIZE(strlen(name) + 1);
    else if (dst_id == KDBUS_DST_ID_BROADCAST)
    	msg_size += KDBUS_PART_HEADER_SIZE + transport->bloom_size;

    msg = malloc(msg_size);
    if (!msg)
    {
    	_dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
		return NULL;
    }

    memset(msg, 0, msg_size);
    msg->size = msg_size;
    msg->payload_type = KDBUS_PAYLOAD_DBUS1;
    msg->dst_id = name ? 0 : dst_id;
    msg->src_id = strtoull(dbus_bus_get_unique_name(transport->base.connection), NULL , 10);

    return msg;
}

/**
 * Builds and sends kdbus message using DBus message.
 * Decide whether used payload vector or memfd memory pool.
 * Handles broadcasts and unicast messages, and passing of Unix fds.
 * Does error handling.
 * TODO refactor to be more compact
 *
 * @param transport transport
 * @param message DBus message to be sent
 * @return size of data sent
 */
static int kdbus_write_msg(DBusTransportKdbus *transport, DBusMessage *message, const char* destination)
{
    struct kdbus_msg *msg;
    struct kdbus_item *item;
    uint64_t dst_id = KDBUS_DST_ID_BROADCAST;
    const DBusString *header;
    const DBusString *body;
    uint64_t ret_size = 0;
    uint64_t body_size = 0;
    uint64_t header_size = 0;
  dbus_bool_t use_memfd = FALSE;
    const int *unix_fds;
    unsigned fds_count;
    dbus_bool_t autostart;

    // determine destination and destination id
    if(destination)
    {
    	dst_id = KDBUS_DST_ID_WELL_KNOWN_NAME;
	  	if((destination[0] == ':') && (destination[1] == '1') && (destination[2] == '.'))  /* if name starts with ":1." it is a unique name and should be send as number */
    	{
    		dst_id = strtoull(&destination[3], NULL, 10);
    		destination = NULL;
    	}    
    }
    
    _dbus_message_get_network_data (message, &header, &body);
    header_size = _dbus_string_get_length(header);
    body_size = _dbus_string_get_length(body);
    ret_size = header_size + body_size;

  // check whether we can and should use memfd
  if((dst_id != KDBUS_DST_ID_BROADCAST) && (ret_size > MEMFD_SIZE_THRESHOLD))
    {
      use_memfd = TRUE;
      kdbus_init_memfd(transport);
    }
    
    _dbus_message_get_unix_fds(message, &unix_fds, &fds_count);

    // init basic message fields
    msg = kdbus_init_msg(destination, dst_id, body_size, use_memfd, fds_count, transport);
    msg->cookie = dbus_message_get_serial(message);
    autostart = dbus_message_get_auto_start (message);
    if(!autostart)
    	msg->flags |= KDBUS_MSG_FLAGS_NO_AUTO_START;
    
    // build message contents
    item = msg->items;

    if(use_memfd)          
    {
        char *buf;

    	if(ioctl(transport->memfd, KDBUS_CMD_MEMFD_SEAL_SET, 0) < 0)
	    {
			_dbus_verbose("memfd sealing failed: \n");
			goto out;
	    }

	    buf = mmap(NULL, ret_size, PROT_WRITE, MAP_SHARED, transport->memfd, 0);
	    if (buf == MAP_FAILED) 
	    {
			_dbus_verbose("mmap() fd=%i failed:%m", transport->memfd);
			goto out;
	    }

			memcpy(buf, _dbus_string_get_const_data(header), header_size);
			if(body_size) {
				buf+=header_size;
				memcpy(buf, _dbus_string_get_const_data(body),  body_size);
				buf-=header_size;
		}

		munmap(buf, ret_size);

		// seal data - kdbus module needs it
		if(ioctl(transport->memfd, KDBUS_CMD_MEMFD_SEAL_SET, 1) < 0) {
			_dbus_verbose("memfd sealing failed: %d (%m)\n", errno);
			ret_size = -1;
			goto out;
		}

	    item->type = KDBUS_MSG_PAYLOAD_MEMFD;
		item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_memfd);
		item->memfd.size = ret_size;
		item->memfd.fd = transport->memfd;
    }
    else
      {
        _dbus_verbose("sending normal vector data\n");
        MSG_ITEM_BUILD_VEC(_dbus_string_get_const_data(header), header_size);

      if(body_size)
        {
          const char* body_data;

          body_data = _dbus_string_get_const_data(body);
          while(body_size > KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE)
            {
              _dbus_verbose("body attaching\n");
              item = KDBUS_PART_NEXT(item);
              MSG_ITEM_BUILD_VEC(body_data, KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE);
              body_data += KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
              body_size -= KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
            }
          if(body_size)
            {
              _dbus_verbose("body attaching\n");
              item = KDBUS_PART_NEXT(item);
              MSG_ITEM_BUILD_VEC(body_data, body_size);
            }
        }
    }

    if(fds_count)
    {
    	item = KDBUS_PART_NEXT(item);
    	item->type = KDBUS_MSG_FDS;
    	item->size = KDBUS_PART_HEADER_SIZE + (sizeof(int) * fds_count);
    	memcpy(item->fds, unix_fds, sizeof(int) * fds_count);
    }

	if (destination)
	{
		item = KDBUS_PART_NEXT(item);
		item->type = KDBUS_MSG_DST_NAME;
		item->size = KDBUS_PART_HEADER_SIZE + strlen(destination) + 1;
		memcpy(item->str, destination, item->size - KDBUS_PART_HEADER_SIZE);
	}
	else if (dst_id == KDBUS_DST_ID_BROADCAST)
	{
		item = KDBUS_PART_NEXT(item);
		item->type = KDBUS_MSG_BLOOM;
		item->size = KDBUS_PART_HEADER_SIZE + transport->bloom_size;
		strncpy(item->data, dbus_message_get_interface(message), transport->bloom_size);
	}

	again:
	if (ioctl(transport->fd, KDBUS_CMD_MSG_SEND, msg))
	{
		if(errno == EINTR)
			goto again;
		else if(errno == ENXIO) //no such id on the bus
		{
            if(!reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Name \"%s\" does not exist", dbus_message_get_destination(message), message, transport->base.connection))
                goto out;
		}
        else if((errno == ESRCH) || (errno = EADDRNOTAVAIL))  //when well known name is not available on the bus
		{
			if(autostart)
			{
				if(!reply_with_error(DBUS_ERROR_SERVICE_UNKNOWN, "The name %s was not provided by any .service files", dbus_message_get_destination(message), message, transport->base.connection))
					goto out;
			}
			else
	            if(!reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Name \"%s\" does not exist", dbus_message_get_destination(message), message, transport->base.connection))
	                goto out;
		}
		_dbus_verbose("kdbus error sending message: err %d (%m)\n", errno);
		ret_size = -1;
	}
out:
    free(msg);
    if(use_memfd)
        close(transport->memfd);

    return ret_size;
}

/**
 * Performs kdbus hello - registration on the kdbus bus
 *
 * @param name place to store unique name given by bus
 * @param transportS transport structure
 * @returns #TRUE on success
 */
static dbus_bool_t bus_register_kdbus(char* name, DBusTransportKdbus* transportS)
{
	struct kdbus_cmd_hello __attribute__ ((__aligned__(8))) hello;

	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD/* |
			   KDBUS_HELLO_ATTACH_COMM |
			   KDBUS_HELLO_ATTACH_EXE |
			   KDBUS_HELLO_ATTACH_CMDLINE |
			   KDBUS_HELLO_ATTACH_CAPS |
			   KDBUS_HELLO_ATTACH_CGROUP |
			   KDBUS_HELLO_ATTACH_SECLABEL |
			   KDBUS_HELLO_ATTACH_AUDIT*/;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = RECEIVE_POOL_SIZE;

	if (ioctl(transportS->fd, KDBUS_CMD_HELLO, &hello))
	{
		_dbus_verbose ("Failed to send hello: %m, %d",errno);
		return FALSE;
	}

	sprintf(name, "%llu", (unsigned long long)hello.id);
	_dbus_verbose("-- Our peer ID is: %s\n", name);
	transportS->bloom_size = hello.bloom_size;

	transportS->kdbus_mmap_ptr = mmap(NULL, RECEIVE_POOL_SIZE, PROT_READ, MAP_SHARED, transportS->fd, 0);
	if (transportS->kdbus_mmap_ptr == MAP_FAILED)
	{
		_dbus_verbose("Error when mmap: %m, %d",errno);
		return FALSE;
	}

	return TRUE;
}

/**
 * Handles messages sent to bus daemon - "org.freedesktop.DBus" and translates them to appropriate
 * kdbus ioctl commands. Than translate kdbus reply into dbus message and put it into recived messages queue.
 *
 * Now it captures only Hello message, which must be handled locally.
 * All the rest is passed to dbus-daemon.
 */
static int emulateOrgFreedesktopDBus(DBusTransport *transport, DBusMessage *message)
{
  if(!strcmp(dbus_message_get_member(message), "Hello"))
    {
      char* name = NULL;

      name = malloc(snprintf(name, 0, "%llu", ULLONG_MAX) + sizeof(":1."));
      if(name == NULL)
        return -1;
      strcpy(name, ":1.");
      if(!bus_register_kdbus(&name[3], (DBusTransportKdbus*)transport))
        goto out;
      if(!register_kdbus_policy(&name[3], transport, geteuid()))
        goto out;

      ((DBusTransportKdbus*)transport)->sender = name;

      if(!reply_1_data(message, DBUS_TYPE_STRING, &name, transport->connection))
        return 0;

    out:
      free(name);
    }
  else
    return 1;  //send to daemon

  return -1;
}

#if KDBUS_MSG_DECODE_DEBUG == 1
static char *msg_id(uint64_t id, char *buf)
{
	if (id == 0)
		return "KERNEL";
	if (id == ~0ULL)
		return "BROADCAST";
	sprintf(buf, "%llu", (unsigned long long)id);
	return buf;
}
#endif
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

/**
 * Puts locally generated message into received data buffer.
 * Use only during receiving phase!
 *
 * @param message message to load
 * @param data place to load message
 * @return size of message
 */
static int put_message_into_data(DBusMessage *message, char* data)
{
	int ret_size;
    const DBusString *header;
    const DBusString *body;
    int size;

    dbus_message_set_serial(message, 1);
    dbus_message_lock (message);
    _dbus_message_get_network_data (message, &header, &body);
    ret_size = _dbus_string_get_length(header);
	memcpy(data, _dbus_string_get_const_data(header), ret_size);
	data += ret_size;
	size = _dbus_string_get_length(body);
	memcpy(data, _dbus_string_get_const_data(body), size);
	ret_size += size;

	return ret_size;
}

/**
 * Get the length of the kdbus message content.
 *
 * @param msg kdbus message
 * @return the length of the kdbus message
 */
static int kdbus_message_size(const struct kdbus_msg* msg)
{
	const struct kdbus_item *item;
	int ret_size = 0;

	KDBUS_PART_FOREACH(item, msg, items)
	{
		if (item->size <= KDBUS_PART_HEADER_SIZE)
		{
			_dbus_verbose("  +%s (%llu bytes) invalid data record\n", enum_MSG(item->type), item->size);
			return -1;
		}
		switch (item->type)
		{
			case KDBUS_MSG_PAYLOAD_OFF:
				ret_size += item->vec.size;
				break;
			case KDBUS_MSG_PAYLOAD_MEMFD:
				ret_size += item->memfd.size;
				break;
			default:
				break;
		}
	}

	return ret_size;
}

/**
 * Decodes kdbus message in order to extract dbus message and put it into data and fds.
 * Also captures and decodes kdbus error messages and kdbus kernel broadcasts and converts
 * all of them into dbus messages.
 *
 * @param msg kdbus message
 * @param data place to copy dbus message to
 * @param kdbus_transport transport
 * @param fds place to store file descriptors received
 * @param n_fds place to store quantity of file descriptor
 * @return number of dbus message's bytes received or -1 on error
 */
static int kdbus_decode_msg(const struct kdbus_msg* msg, char *data, DBusTransportKdbus* kdbus_transport, int* fds, int* n_fds)
{
	const struct kdbus_item *item;
	int ret_size = 0;
	DBusMessage *message = NULL;
	DBusMessageIter args;
	const char* emptyString = "";
    const char* pString = NULL;
	char dbus_name[(unsigned int)(snprintf((char*)pString, 0, "%llu", ULLONG_MAX) + sizeof(":1."))];
	const char* pDBusName = dbus_name;
#if KDBUS_MSG_DECODE_DEBUG == 1
	char buf[32];
#endif

#if KDBUS_MSG_DECODE_DEBUG == 1
	_dbus_verbose("MESSAGE: %s (%llu bytes) flags=0x%llx, %s → %s, cookie=%llu, timeout=%llu\n",
		enum_PAYLOAD(msg->payload_type), (unsigned long long) msg->size,
		(unsigned long long) msg->flags,
		msg_id(msg->src_id, buf), msg_id(msg->dst_id, buf),
		(unsigned long long) msg->cookie, (unsigned long long) msg->timeout_ns);
#endif

	*n_fds = 0;

	KDBUS_PART_FOREACH(item, msg, items)
	{
		if (item->size <= KDBUS_PART_HEADER_SIZE)
		{
			_dbus_verbose("  +%s (%llu bytes) invalid data record\n", enum_MSG(item->type), item->size);
			break;  //??? continue (because dbus will find error) or break
		}

		switch (item->type)
		{
			case KDBUS_MSG_PAYLOAD_OFF:
				memcpy(data, (char *)kdbus_transport->kdbus_mmap_ptr + item->vec.offset, item->vec.size);
				data += item->vec.size;
				ret_size += item->vec.size;

				_dbus_verbose("  +%s (%llu bytes) off=%llu size=%llu\n",
					enum_MSG(item->type), item->size,
					(unsigned long long)item->vec.offset,
					(unsigned long long)item->vec.size);
			break;

			case KDBUS_MSG_PAYLOAD_MEMFD:
			{
				char *buf;
				uint64_t size;

				size = item->memfd.size;
				_dbus_verbose("memfd.size : %llu\n", (unsigned long long)size);

				buf = mmap(NULL, size, PROT_READ , MAP_SHARED, item->memfd.fd, 0);
				if (buf == MAP_FAILED)
				{
					_dbus_verbose("mmap() fd=%i failed:%m", item->memfd.fd);
					return -1;
				}

				memcpy(data, buf, size);
				data += size;
				ret_size += size;

				munmap(buf, size);

                _dbus_verbose("  +%s (%llu bytes) off=%llu size=%llu\n",
					   enum_MSG(item->type), item->size,
					   (unsigned long long)item->vec.offset,
					   (unsigned long long)item->vec.size);
			break;
			}

			case KDBUS_MSG_FDS:
			{
				int i;

				*n_fds = (item->size - KDBUS_PART_HEADER_SIZE) / sizeof(int);
				memcpy(fds, item->fds, *n_fds * sizeof(int));
	            for (i = 0; i < *n_fds; i++)
	              _dbus_fd_set_close_on_exec(fds[i]);
			break;
			}

#if KDBUS_MSG_DECODE_DEBUG == 1
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
				__u64 size = item->size - KDBUS_PART_HEADER_SIZE;
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
#endif

			case KDBUS_MSG_REPLY_TIMEOUT:
				_dbus_verbose("  +%s (%llu bytes) cookie=%llu\n",
					   enum_MSG(item->type), item->size, msg->cookie_reply);

				message = generate_local_error_message(msg->cookie_reply, DBUS_ERROR_NO_REPLY, NULL);
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				ret_size = put_message_into_data(message, data);
			break;

			case KDBUS_MSG_REPLY_DEAD:
				_dbus_verbose("  +%s (%llu bytes) cookie=%llu\n",
					   enum_MSG(item->type), item->size, msg->cookie_reply);

				message = generate_local_error_message(msg->cookie_reply, DBUS_ERROR_NAME_HAS_NO_OWNER, NULL);
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				ret_size = put_message_into_data(message, data);
			break;

			case KDBUS_MSG_NAME_ADD:
				_dbus_verbose("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, flags=0x%llx\n",
					enum_MSG(item->type), (unsigned long long) item->size,
					item->name_change.name, item->name_change.old_id,
					item->name_change.new_id, item->name_change.flags);

				message = dbus_message_new_signal(DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameOwnerChanged");
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				sprintf(dbus_name,":1.%llu",item->name_change.new_id);
				pString = item->name_change.name;
				_dbus_verbose ("Name added: %s\n", pString);
			    dbus_message_iter_init_append(message, &args);
			    ITER_APPEND_STR(pString)
			    ITER_APPEND_STR(emptyString)
			    ITER_APPEND_STR(pDBusName)
				dbus_message_set_sender(message, DBUS_SERVICE_DBUS);

				ret_size = put_message_into_data(message, data);
			break;

			case KDBUS_MSG_NAME_REMOVE:
				_dbus_verbose("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, flags=0x%llx\n",
					enum_MSG(item->type), (unsigned long long) item->size,
					item->name_change.name, item->name_change.old_id,
					item->name_change.new_id, item->name_change.flags);

				message = dbus_message_new_signal(DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameOwnerChanged"); // name of the signal
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				sprintf(dbus_name,":1.%llu",item->name_change.old_id);
				pString = item->name_change.name;
				_dbus_verbose ("Name removed: %s\n", pString);
			    dbus_message_iter_init_append(message, &args);
			    ITER_APPEND_STR(pString)
			    ITER_APPEND_STR(pDBusName)
			    ITER_APPEND_STR(emptyString)
				dbus_message_set_sender(message, DBUS_SERVICE_DBUS);

				ret_size = put_message_into_data(message, data);
			break;

			case KDBUS_MSG_NAME_CHANGE:
				_dbus_verbose("  +%s (%llu bytes) '%s', old id=%lld, new id=%lld, flags=0x%llx\n",
					enum_MSG(item->type), (unsigned long long) item->size,
					item->name_change.name, item->name_change.old_id,
					item->name_change.new_id, item->name_change.flags);

				message = dbus_message_new_signal(DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameOwnerChanged");
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				sprintf(dbus_name,":1.%llu",item->name_change.old_id);
				pString = item->name_change.name;
				_dbus_verbose ("Name changed: %s\n", pString);
			    dbus_message_iter_init_append(message, &args);
			    ITER_APPEND_STR(pString)
			    ITER_APPEND_STR(pDBusName)
			    sprintf(&dbus_name[3],"%llu",item->name_change.new_id);
			    _dbus_verbose ("New id: %s\n", pDBusName);
			    ITER_APPEND_STR(pDBusName)
				dbus_message_set_sender(message, DBUS_SERVICE_DBUS);

				ret_size = put_message_into_data(message, data);
			break;

			case KDBUS_MSG_ID_ADD:
				_dbus_verbose("  +%s (%llu bytes) id=%llu flags=%llu\n",
					   enum_MSG(item->type), (unsigned long long) item->size,
					   (unsigned long long) item->id_change.id,
					   (unsigned long long) item->id_change.flags);

				message = dbus_message_new_signal(DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameOwnerChanged");
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				sprintf(dbus_name,":1.%llu",item->id_change.id);
			    dbus_message_iter_init_append(message, &args);
			    ITER_APPEND_STR(pDBusName)
			    ITER_APPEND_STR(emptyString)
			    ITER_APPEND_STR(pDBusName)
				dbus_message_set_sender(message, DBUS_SERVICE_DBUS);

				ret_size = put_message_into_data(message, data);
			break;

			case KDBUS_MSG_ID_REMOVE:
				_dbus_verbose("  +%s (%llu bytes) id=%llu flags=%llu\n",
					   enum_MSG(item->type), (unsigned long long) item->size,
					   (unsigned long long) item->id_change.id,
					   (unsigned long long) item->id_change.flags);

				message = dbus_message_new_signal(DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameOwnerChanged");
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				sprintf(dbus_name,":1.%llu",item->id_change.id);
			    dbus_message_iter_init_append(message, &args);
			    ITER_APPEND_STR(pDBusName)
			    ITER_APPEND_STR(pDBusName)
			    ITER_APPEND_STR(emptyString)
				dbus_message_set_sender(message, DBUS_SERVICE_DBUS);

				ret_size = put_message_into_data(message, data);
			break;
#if KDBUS_MSG_DECODE_DEBUG == 1
			default:
				_dbus_verbose("  +%s (%llu bytes)\n", enum_MSG(item->type), item->size);
			break;
#endif
		}
	}

#if KDBUS_MSG_DECODE_DEBUG == 1

	if ((char *)item - ((char *)msg + msg->size) >= 8)
		_dbus_verbose("invalid padding at end of message\n");
#endif

out:
	if(message)
		dbus_message_unref(message);
	return ret_size;
}

/**
 * Reads message from kdbus and puts it into dbus buffer and fds
 *
 * @param transport transport
 * @param buffer place to copy received message to
 * @param fds place to store file descriptors sent in the message
 * @param n_fds place  to store number of file descriptors
 * @return size of received message on success, -1 on error
 */
static int kdbus_read_message(DBusTransportKdbus *socket_transport, DBusString *buffer, int* fds, int* n_fds)
{
	int ret_size, buf_size;
	uint64_t __attribute__ ((__aligned__(8))) offset;
	struct kdbus_msg *msg;
	char *data;
	int start;

	start = _dbus_string_get_length (buffer);

	again:
	if (ioctl(socket_transport->fd, KDBUS_CMD_MSG_RECV, &offset) < 0)
	{
		if(errno == EINTR)
			goto again;
		_dbus_verbose("kdbus error receiving message: %d (%m)\n", errno);
		_dbus_string_set_length (buffer, start);
		return -1;
	}

	msg = (struct kdbus_msg *)((char*)socket_transport->kdbus_mmap_ptr + offset);

	buf_size = kdbus_message_size(msg);
	if (buf_size == -1)
	{
		_dbus_verbose("kdbus error - too short message: %d (%m)\n", errno);
		return -1;
	}

	/* What is the maximum size of the locally generated message?
	   I just assume 2048 bytes */
	buf_size = MAX(buf_size, 2048);

	if (!_dbus_string_lengthen (buffer, buf_size))
	{
		errno = ENOMEM;
		return -1;
	}
	data = _dbus_string_get_data_len (buffer, start, buf_size);

	ret_size = kdbus_decode_msg(msg, data, socket_transport, fds, n_fds);

	if(ret_size == -1) /* error */
	{
		_dbus_string_set_length (buffer, start);
		return -1;
	}
	else if (buf_size != ret_size) /* case of locally generated message */
	{
		_dbus_string_set_length (buffer, start + ret_size);
	}

	again2:
	if (ioctl(socket_transport->fd, KDBUS_CMD_MSG_RELEASE, &offset) < 0)
	{
		if(errno == EINTR)
			goto again2;
		_dbus_verbose("kdbus error freeing message: %d (%m)\n", errno);
		return -1;
	}

	return ret_size;
}
/*
 * copy-paste from socket transport with needed renames only.
 */
static void
free_watches (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  _dbus_verbose ("start\n");

  if (kdbus_transport->read_watch)
    {
      if (transport->connection)
        _dbus_connection_remove_watch_unlocked (transport->connection,
                                                kdbus_transport->read_watch);
      _dbus_watch_invalidate (kdbus_transport->read_watch);
      _dbus_watch_unref (kdbus_transport->read_watch);
      kdbus_transport->read_watch = NULL;
    }

  if (kdbus_transport->write_watch)
    {
      if (transport->connection)
        _dbus_connection_remove_watch_unlocked (transport->connection,
                                                kdbus_transport->write_watch);
      _dbus_watch_invalidate (kdbus_transport->write_watch);
      _dbus_watch_unref (kdbus_transport->write_watch);
      kdbus_transport->write_watch = NULL;
    }

  _dbus_verbose ("end\n");
}

/*
 * copy-paste from socket transport with needed renames only.
 */
static void
transport_finalize (DBusTransport *transport)
{
  _dbus_verbose ("\n");

  free_watches (transport);

  _dbus_transport_finalize_base (transport);

  _dbus_assert (((DBusTransportKdbus*) transport)->read_watch == NULL);
  _dbus_assert (((DBusTransportKdbus*) transport)->write_watch == NULL);

  dbus_free (transport);
}

/*
 * copy-paste from socket transport with needed renames only.
 */
static void
check_write_watch (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  dbus_bool_t needed;

  if (transport->connection == NULL)
    return;

  if (transport->disconnected)
    {
      _dbus_assert (kdbus_transport->write_watch == NULL);
      return;
    }

  _dbus_transport_ref (transport);

  needed = _dbus_connection_has_messages_to_send_unlocked (transport->connection);

  _dbus_verbose ("check_write_watch(): needed = %d on connection %p watch %p fd = %d outgoing messages exist %d\n",
                 needed, transport->connection, kdbus_transport->write_watch,
                 kdbus_transport->fd,
                 _dbus_connection_has_messages_to_send_unlocked (transport->connection));

  _dbus_connection_toggle_watch_unlocked (transport->connection,
                                          kdbus_transport->write_watch,
                                          needed);

  _dbus_transport_unref (transport);
}

/*
 * copy-paste from socket transport with needed renames only.
 */
static void
check_read_watch (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  dbus_bool_t need_read_watch;

  _dbus_verbose ("fd = %d\n",kdbus_transport->fd);

  if (transport->connection == NULL)
    return;

  if (transport->disconnected)
    {
      _dbus_assert (kdbus_transport->read_watch == NULL);
      return;
    }

  _dbus_transport_ref (transport);

   need_read_watch =
      (_dbus_counter_get_size_value (transport->live_messages) < transport->max_live_messages_size) &&
      (_dbus_counter_get_unix_fd_value (transport->live_messages) < transport->max_live_messages_unix_fds);

  _dbus_verbose ("  setting read watch enabled = %d\n", need_read_watch);
  _dbus_connection_toggle_watch_unlocked (transport->connection,
                                          kdbus_transport->read_watch,
                                          need_read_watch);

  _dbus_transport_unref (transport);
}

/*
 * copy-paste from socket transport.
 */
static void
do_io_error (DBusTransport *transport)
{
  _dbus_transport_ref (transport);
  _dbus_transport_disconnect (transport);
  _dbus_transport_unref (transport);
}

/* returns false on oom */
static dbus_bool_t
do_writing (DBusTransport *transport)
{
	DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
	dbus_bool_t oom;

	if (transport->disconnected)
    {
		_dbus_verbose ("Not connected, not writing anything\n");
		return TRUE;
    }

#if 1
	_dbus_verbose ("do_writing(), have_messages = %d, fd = %d\n",
                 _dbus_connection_has_messages_to_send_unlocked (transport->connection),
                 kdbus_transport->fd);
#endif

	oom = FALSE;

	while (!transport->disconnected && _dbus_connection_has_messages_to_send_unlocked (transport->connection))
    {
		int bytes_written;
		DBusMessage *message;
		const DBusString *header;
		const DBusString *body;
		int total_bytes_to_write;
		const char* pDestination;

		message = _dbus_connection_get_message_to_send (transport->connection);
		_dbus_assert (message != NULL);
		if(dbus_message_get_sender(message) == NULL)  //needed for daemon to pass pending activation messages
		{
            dbus_message_unlock(message);
            dbus_message_set_sender(message, kdbus_transport->sender);
            dbus_message_lock (message);
		}
		_dbus_message_get_network_data (message, &header, &body);
		total_bytes_to_write = _dbus_string_get_length(header) + _dbus_string_get_length(body);
		pDestination = dbus_message_get_destination(message);

		if(pDestination)
		{
			if(!strcmp(pDestination, DBUS_SERVICE_DBUS))
			{
				if(!strcmp(dbus_message_get_interface(message), DBUS_INTERFACE_DBUS))
				{
					int ret;

					ret = emulateOrgFreedesktopDBus(transport, message);
					if(ret < 0)
					{
						bytes_written = -1;
						goto written;
					}
					else if(ret == 0)
					{
						bytes_written = total_bytes_to_write;
						goto written;
					}
					//else send to "daemon" as to normal recipient
				}
			}
		}

		if(total_bytes_to_write > kdbus_transport->max_bytes_written_per_iteration)
		  return -E2BIG;

		bytes_written = kdbus_write_msg(kdbus_transport, message, pDestination);


written:
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
				_dbus_verbose ("Error writing to remote app: %s\n", _dbus_strerror_from_errno ());
				do_io_error (transport);
				goto out;
			}
		}
		else
		{
			_dbus_verbose (" wrote %d bytes of %d\n", bytes_written,
                         total_bytes_to_write);

			kdbus_transport->message_bytes_written += bytes_written;

			_dbus_assert (kdbus_transport->message_bytes_written <=
                        total_bytes_to_write);

			  if (kdbus_transport->message_bytes_written == total_bytes_to_write)
			  {
				  kdbus_transport->message_bytes_written = 0;
				  _dbus_connection_message_sent_unlocked (transport->connection,
														  message);
			  }
		}
    }

	out:
	if (oom)
		return FALSE;
	return TRUE;
}

/* returns false on out-of-memory */
static dbus_bool_t
do_reading (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
  DBusString *buffer;
  int bytes_read;
  dbus_bool_t oom = FALSE;
  int *fds, n_fds;

  _dbus_verbose ("fd = %d\n",kdbus_transport->fd);

 again:

  /* See if we've exceeded max messages and need to disable reading */
  check_read_watch (transport);

  _dbus_assert (kdbus_transport->read_watch != NULL ||
                transport->disconnected);

  if (transport->disconnected)
    goto out;

  if (!dbus_watch_get_enabled (kdbus_transport->read_watch))
    return TRUE;

  if (!_dbus_message_loader_get_unix_fds(transport->loader, &fds, &n_fds))
  {
      _dbus_verbose ("Out of memory reading file descriptors\n");
      oom = TRUE;
      goto out;
  }
  _dbus_message_loader_get_buffer (transport->loader, &buffer);

  bytes_read = kdbus_read_message(kdbus_transport, buffer, fds, &n_fds);

  if (bytes_read >= 0 && n_fds > 0)
    _dbus_verbose("Read %i unix fds\n", n_fds);

  _dbus_message_loader_return_buffer (transport->loader,
                                      buffer,
                                      bytes_read < 0 ? 0 : bytes_read);
  _dbus_message_loader_return_unix_fds(transport->loader, fds, bytes_read < 0 ? 0 : n_fds);

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
      do_io_error (transport);
      goto out;
    }
  else
    {
      _dbus_verbose (" read %d bytes\n", bytes_read);

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
  return TRUE;
}

/*
 * copy-paste from socket transport.
 */
static dbus_bool_t
unix_error_with_read_to_come (DBusTransport *itransport,
                              DBusWatch     *watch,
                              unsigned int   flags)
{
   DBusTransportKdbus *transport = (DBusTransportKdbus *) itransport;

   if (!((flags & DBUS_WATCH_HANGUP) || (flags & DBUS_WATCH_ERROR)))
      return FALSE;

  /* If we have a read watch enabled ...
     we -might have data incoming ... => handle the HANGUP there */
   if (watch != transport->read_watch && _dbus_watch_get_enabled (transport->read_watch))
      return FALSE;

   return TRUE;
}

/*
 * copy-paste from socket transport with needed renames only.
 */
static dbus_bool_t
kdbus_handle_watch (DBusTransport *transport,
                   DBusWatch     *watch,
                   unsigned int   flags)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  _dbus_assert (watch == kdbus_transport->read_watch ||
                watch == kdbus_transport->write_watch);
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

  if (watch == kdbus_transport->read_watch &&
      (flags & DBUS_WATCH_READABLE))
    {
      _dbus_verbose ("handling read watch %p flags = %x\n",
                     watch, flags);

	  if (!do_reading (transport))
	    {
	      _dbus_verbose ("no memory to read\n");
	      return FALSE;
	    }

    }
  else if (watch == kdbus_transport->write_watch &&
           (flags & DBUS_WATCH_WRITABLE))
    {
      _dbus_verbose ("handling write watch, have_outgoing_messages = %d\n",
                     _dbus_connection_has_messages_to_send_unlocked (transport->connection));

      if (!do_writing (transport))
        {
          _dbus_verbose ("no memory to write\n");
          return FALSE;
        }

      /* See if we still need the write watch */
      check_write_watch (transport);
    }

  return TRUE;
}

/*
 * copy-paste from socket transport with needed renames only.
 */
static void
kdbus_disconnect (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  _dbus_verbose ("\n");

  free_watches (transport);

  _dbus_close_socket (kdbus_transport->fd, NULL);
  kdbus_transport->fd = -1;
}

/*
 * copy-paste from socket transport with needed renames only.
 */
static dbus_bool_t
kdbus_connection_set (DBusTransport *transport)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  dbus_connection_set_is_authenticated(transport->connection); //now we don't have authentication in kdbus

  _dbus_watch_set_handler (kdbus_transport->write_watch,
                           _dbus_connection_handle_watch,
                           transport->connection, NULL);

  _dbus_watch_set_handler (kdbus_transport->read_watch,
                           _dbus_connection_handle_watch,
                           transport->connection, NULL);

  if (!_dbus_connection_add_watch_unlocked (transport->connection,
                                            kdbus_transport->write_watch))
    return FALSE;

  if (!_dbus_connection_add_watch_unlocked (transport->connection,
                                            kdbus_transport->read_watch))
    {
      _dbus_connection_remove_watch_unlocked (transport->connection,
                                              kdbus_transport->write_watch);
      return FALSE;
    }

  check_read_watch (transport);
  check_write_watch (transport);

  return TRUE;
}

/**  original dbus copy-pasted comment
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
	DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;
	DBusPollFD poll_fd;
	int poll_res;
	int poll_timeout;

	_dbus_verbose (" iteration flags = %s%s timeout = %d read_watch = %p write_watch = %p fd = %d\n",
                 flags & DBUS_ITERATION_DO_READING ? "read" : "",
                 flags & DBUS_ITERATION_DO_WRITING ? "write" : "",
                 timeout_milliseconds,
                 kdbus_transport->read_watch,
                 kdbus_transport->write_watch,
                 kdbus_transport->fd);

  /* the passed in DO_READING/DO_WRITING flags indicate whether to
   * read/write messages, but regardless of those we may need to block
   * for reading/writing to do auth.  But if we do reading for auth,
   * we don't want to read any messages yet if not given DO_READING.
   */

   poll_fd.fd = kdbus_transport->fd;
   poll_fd.events = 0;

   if (_dbus_transport_try_to_authenticate (transport))
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
      _dbus_assert (kdbus_transport->read_watch);
      if (flags & DBUS_ITERATION_DO_READING)
	     poll_fd.events |= _DBUS_POLLIN;

      _dbus_assert (kdbus_transport->write_watch);
      if (flags & DBUS_ITERATION_DO_WRITING)
         poll_fd.events |= _DBUS_POLLOUT;
   }
   else
   {
      DBusAuthState auth_state;

      auth_state = _dbus_auth_do_work (transport->auth);

      if (transport->receive_credentials_pending || auth_state == DBUS_AUTH_STATE_WAITING_FOR_INPUT)
	     poll_fd.events |= _DBUS_POLLIN;

      if (transport->send_credentials_pending || auth_state == DBUS_AUTH_STATE_HAVE_BYTES_TO_SEND)
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

    again:
      poll_res = _dbus_poll (&poll_fd, 1, poll_timeout);

      if (poll_res < 0 && _dbus_get_is_errno_eintr ())
      {
         _dbus_verbose ("Error from _dbus_poll(): %s\n", _dbus_strerror_from_errno ());
    	 goto again;
      }

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

            _dbus_verbose ("in iteration, need_read=%d need_write=%d\n",
                             need_read, need_write);

            if (need_read && (flags & DBUS_ITERATION_DO_READING))
               do_reading (transport);
            if (need_write && (flags & DBUS_ITERATION_DO_WRITING))
               do_writing (transport);
         }
      }
      else
         _dbus_verbose ("Error from _dbus_poll(): %s\n", _dbus_strerror_from_errno ());
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

/*
 * copy-paste from socket transport with needed renames only.
 */
static void
kdbus_live_messages_changed (DBusTransport *transport)
{
  /* See if we should look for incoming messages again */
  check_read_watch (transport);
}

static dbus_bool_t
kdbus_get_kdbus_fd (DBusTransport *transport,
                      int           *fd_p)
{
  DBusTransportKdbus *kdbus_transport = (DBusTransportKdbus*) transport;

  *fd_p = kdbus_transport->fd;

  return TRUE;
}

static const DBusTransportVTable kdbus_vtable = {
  transport_finalize,
  kdbus_handle_watch,
  kdbus_disconnect,
  kdbus_connection_set,
  kdbus_do_iteration,
  kdbus_live_messages_changed,
  kdbus_get_kdbus_fd
};

/**
 * Creates a new transport for the given kdbus file descriptor.  The file
 * descriptor must be nonblocking.
 *
 * @param fd the file descriptor.
 * @param address the transport's address
 * @returns the new transport, or #NULL if no memory.
 */
static DBusTransport*
_dbus_transport_new_kdbus_transport (int fd, const DBusString *address)
{
	DBusTransportKdbus *kdbus_transport;

  kdbus_transport = dbus_new0 (DBusTransportKdbus, 1);
  if (kdbus_transport == NULL)
    return NULL;

  kdbus_transport->write_watch = _dbus_watch_new (fd,
                                                 DBUS_WATCH_WRITABLE,
                                                 FALSE,
                                                 NULL, NULL, NULL);
  if (kdbus_transport->write_watch == NULL)
    goto failed_2;

  kdbus_transport->read_watch = _dbus_watch_new (fd,
                                                DBUS_WATCH_READABLE,
                                                FALSE,
                                                NULL, NULL, NULL);
  if (kdbus_transport->read_watch == NULL)
    goto failed_3;

  if (!_dbus_transport_init_base (&kdbus_transport->base,
                                  &kdbus_vtable,
                                  NULL, address))
    goto failed_4;

  kdbus_transport->fd = fd;
  kdbus_transport->message_bytes_written = 0;

  /* These values should probably be tunable or something. */
  kdbus_transport->max_bytes_read_per_iteration = DBUS_MAXIMUM_MESSAGE_LENGTH;
  kdbus_transport->max_bytes_written_per_iteration = DBUS_MAXIMUM_MESSAGE_LENGTH;

  kdbus_transport->kdbus_mmap_ptr = NULL;
  kdbus_transport->memfd = -1;
  
  return (DBusTransport*) kdbus_transport;

 failed_4:
  _dbus_watch_invalidate (kdbus_transport->read_watch);
  _dbus_watch_unref (kdbus_transport->read_watch);
 failed_3:
  _dbus_watch_invalidate (kdbus_transport->write_watch);
  _dbus_watch_unref (kdbus_transport->write_watch);
 failed_2:
  dbus_free (kdbus_transport);
  return NULL;
}

/**
 * Opens a connection to the kdbus bus
 *
 * This will set FD_CLOEXEC for the socket returned.
 *
 * @param path the path to UNIX domain socket
 * @param error return location for error code
 * @returns connection file descriptor or -1 on error
 */
static int _dbus_connect_kdbus (const char *path, DBusError *error)
{
	int fd;

	_DBUS_ASSERT_ERROR_IS_CLEAR (error);
	_dbus_verbose ("connecting to kdbus bus %s\n", path);

	fd = open(path, O_RDWR|O_CLOEXEC|O_NONBLOCK);
	if (fd < 0)
		dbus_set_error(error, _dbus_error_from_errno (errno), "Failed to open file descriptor: %s", _dbus_strerror (errno));

	return fd;
}

/**
 * Creates a new transport for kdbus.
 * This creates a client-side of a transport.
 *
 * @param path the path to the bus.
 * @param error address where an error can be returned.
 * @returns a new transport, or #NULL on failure.
 */
static DBusTransport* _dbus_transport_new_for_kdbus (const char *path, DBusError *error)
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

	transport = _dbus_transport_new_kdbus_transport (fd, &address);
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
 * Opens kdbus transport if method from address entry is kdbus
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
