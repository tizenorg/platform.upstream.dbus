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
#include <openssl/md5.h>

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_PART_HEADER_SIZE)

#define KDBUS_PART_NEXT(part) \
	(typeof(part))(((uint8_t *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_PART_FOREACH(part, head, first)				\
	for (part = (head)->first;					\
	     (uint8_t *)(part) < (uint8_t *)(head) + (head)->size;	\
	     part = KDBUS_PART_NEXT(part))
#define RECEIVE_POOL_SIZE (10 * 1024LU * 1024LU)
#define MEMFD_SIZE_THRESHOLD (2 * 1024 * 1024LU) // over this memfd is used

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

  int max_bytes_read_per_iteration;     /**< In kdbus only to control overall message size*/
  int max_bytes_written_per_iteration;  /**< In kdbus only to control overall message size*/

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

static dbus_bool_t
socket_get_socket_fd (DBusTransport *transport,
                      int           *fd_p)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  *fd_p = socket_transport->fd;

  return TRUE;
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

static int reply_ack(DBusMessage *message, DBusConnection* connection)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if(reply == NULL)
		return -1;
    if(add_message_to_received(reply, connection))
    	return 0;
    return -1;
}

/**
 * Retrieves file descriptor to memory pool from kdbus module.
 * It is then used for bulk data sending.
 * Triggered when message payload is over MEMFD_SIZE_THRESHOLD
 * 
 */
static int kdbus_init_memfd(DBusTransportSocket* socket_transport)
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
static struct kdbus_msg* kdbus_init_msg(const char* name, __u64 dst_id, uint64_t body_size, dbus_bool_t use_memfd, int fds_count, DBusTransportSocket *transport)
{
    struct kdbus_msg* msg;
    uint64_t msg_size;

    msg_size = sizeof(struct kdbus_msg);

    if(use_memfd == TRUE)  // bulk data - memfd - encoded and plain
        msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_memfd));
    else {
        msg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
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
 * Builds and sends kdbus message using Dbus message.
 * Decide whether used payload vector or memfd memory pool.
 * Handles broadcasts and unicast messages, and passing of Unix fds.
 * Does error handling.
 * TODO refactor to be more compact
 *
 * @param transport transport
 * @param message DBus message to be sent
 * @param encoded flag if the message is encoded
 * @return size of data sent
 */
static int kdbus_write_msg(DBusTransportSocket *transport, DBusMessage *message, dbus_bool_t encoded)
{
    struct kdbus_msg *msg;
    struct kdbus_item *item;
    const char *name;
    uint64_t dst_id = KDBUS_DST_ID_BROADCAST;
    const DBusString *header;
    const DBusString *body;
    uint64_t ret_size = 0;
    uint64_t body_size = 0;
    uint64_t header_size = 0;
    dbus_bool_t use_memfd;
    const int *unix_fds;
    unsigned fds_count;
    dbus_bool_t autostart;

    // determine name and destination id
    if((name = dbus_message_get_destination(message)))
    {
    	dst_id = KDBUS_DST_ID_WELL_KNOWN_NAME;
	  	if((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))  /* if name starts with ":1." it is a unique name and should be send as number */
    	{
    		dst_id = strtoull(&name[3], NULL, 10);
    		name = NULL;
    	}    
    }
    
    // get size of data
    if(encoded)
        ret_size = _dbus_string_get_length (&transport->encoded_outgoing);
    else
    {
        _dbus_message_get_network_data (message, &header, &body);
        header_size = _dbus_string_get_length(header);
        body_size = _dbus_string_get_length(body);
        ret_size = header_size + body_size;
    }

    // check if message size is big enough to use memfd kdbus transport
    use_memfd = ret_size > MEMFD_SIZE_THRESHOLD ? TRUE : FALSE;
    if(use_memfd) kdbus_init_memfd(transport);
    
    _dbus_message_get_unix_fds(message, &unix_fds, &fds_count);

    // init basic message fields
    msg = kdbus_init_msg(name, dst_id, body_size, use_memfd, fds_count, transport);
    msg->cookie = dbus_message_get_serial(message);
    autostart = dbus_message_get_auto_start (message);
    if(!autostart)
    	msg->flags |= KDBUS_MSG_FLAGS_NO_AUTO_START;
    
    // build message contents
    item = msg->items;

    // case 1 - bulk data transfer - memfd - encoded and plain
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

		if(encoded)
			memcpy(buf, &transport->encoded_outgoing, ret_size);
		else
		{
			memcpy(buf, _dbus_string_get_const_data(header), header_size);
			if(body_size) {
				buf+=header_size;
				memcpy(buf, _dbus_string_get_const_data(body),  body_size);
				buf-=header_size;
			}
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
    // case 2 - small encoded - don't use memfd
    } else if(encoded) { 
        _dbus_verbose("sending encoded data\n");
        MSG_ITEM_BUILD_VEC(&transport->encoded_outgoing, _dbus_string_get_length (&transport->encoded_outgoing));

    // case 3 - small not encoded - don't use memfd
    } else { 
        _dbus_verbose("sending normal vector data\n");
        MSG_ITEM_BUILD_VEC(_dbus_string_get_const_data(header), header_size);

        if(body_size)
        {
            _dbus_verbose("body attaching\n");
	    item = KDBUS_PART_NEXT(item);
	    MSG_ITEM_BUILD_VEC(_dbus_string_get_const_data(body), body_size);
        }
    }

    if(fds_count)
    {
    	item = KDBUS_PART_NEXT(item);
    	item->type = KDBUS_MSG_FDS;
    	item->size = KDBUS_PART_HEADER_SIZE + (sizeof(int) * fds_count);
    	memcpy(item->fds, unix_fds, sizeof(int) * fds_count);
    }

	if (name)
	{
		item = KDBUS_PART_NEXT(item);
		item->type = KDBUS_MSG_DST_NAME;
		item->size = KDBUS_PART_HEADER_SIZE + strlen(name) + 1;
		strcpy(item->str, name);
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
		if((errno == ESRCH) || (errno == ENXIO) || (errno = EADDRNOTAVAIL))  //when recipient is not available on the bus
		{
			if(autostart)
			{
				//todo start service here, otherwise
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
    close(transport->memfd);

    return ret_size;
}

struct nameInfo
{
	__u64 uniqueId;
	__u64 userId;
	__u64 processId;
	__u32 sec_label_len;
	char *sec_label;
};

/**
 * Performs kdbus query of id of the given name
 *
 * @param name name to query for
 * @param fd bus file
 * @param ownerID place to store id of the name
 * @return 0 on success, -errno if failed
 */
static int kdbus_NameQuery(char* name, int fd, struct nameInfo* pInfo)
{
	struct kdbus_cmd_name_info *msg;
	struct kdbus_item *item;
	uint64_t size;
	int ret;
	uint64_t item_size;

	pInfo->sec_label_len = 0;
	pInfo->sec_label = NULL;
	
    item_size = KDBUS_PART_HEADER_SIZE + strlen(name) + 1;
	item_size = (item_size < 56) ? 56 : item_size;  //at least 56 bytes are needed by kernel to place info about name, otherwise error
    size = sizeof(struct kdbus_cmd_name_info) + item_size;

	msg = malloc(size);
	if (!msg)
	{
		_dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
		return -1;
	}

	memset(msg, 0, size);
	msg->size = size;
  	if((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))  /* if name starts with ":1." it is a unique name and should be send as number */
  		msg->id = strtoull(&name[3], NULL, 10);
  	else
  		msg->id = 0;

	item = msg->items;
	item->type = KDBUS_NAME_INFO_ITEM_NAME;
	item->size = item_size;
	strcpy(item->str, name);

	again:
	ret = ioctl(fd, KDBUS_CMD_NAME_QUERY, msg);
	if (ret < 0)
	{
		if(errno == EINTR)
			goto again;
		else if(ret == -ENOBUFS)
		{
			msg = realloc(msg, msg->size);  //prepare memory
			if(msg != NULL)
				goto again;
		}
		pInfo->uniqueId = 0;
		ret = -errno;
	}
	else
	{
		pInfo->uniqueId = msg->id;
		pInfo->userId = msg->creds.uid;
		pInfo->processId = msg->creds.pid;
_dbus_verbose ("I'm alive 1\n");
		item = msg->items;
		while((uint8_t *)(item) < (uint8_t *)(msg) + msg->size)
		{
			if(item->type == KDBUS_NAME_INFO_ITEM_SECLABEL)
			{
				pInfo->sec_label_len = item->size - KDBUS_PART_HEADER_SIZE - 1;
				if(pInfo->sec_label_len != 0)
					pInfo->sec_label = malloc(pInfo->sec_label_len);
				if(pInfo->sec_label == NULL)
					ret = -1;
				else
					memcpy(pInfo->sec_label, item->data, pInfo->sec_label_len);
					
				break;
			}
			item = KDBUS_PART_NEXT(item);
		}
	}

	free(msg);
	return ret;
}

static struct kdbus_policy *make_policy_name(const char *name)
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

static struct kdbus_policy *make_policy_access(__u64 type, __u64 bits, __u64 id)
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

static void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_policy *policy, __u64 max_size)
{
	struct kdbus_policy *dst = (struct kdbus_policy *) ((char *) cmd_policy + cmd_policy->size);

	if (cmd_policy->size + policy->size > max_size)
		return;

	memcpy(dst, policy, policy->size);
	cmd_policy->size += KDBUS_ALIGN8(policy->size);
	free(policy);
}

/**
 * Registers kdbus policy for given connection.
 *
 * Policy sets rights of the name (unique or well known) on the bus. Without policy it is
 * not possible to send or receive messages. It must be set separately for unique id and
 * well known name of the connection. It is set after registering on the bus, but before
 * requesting for name. The policy is valid for the given name, not for the connection.
 *
 * Name of the policy equals name on the bus.
 *
 * @param name name of the policy = name of the connection
 * @param connection the connection
 * @param error place to store errors
 *
 * @returns #TRUE on success
 */
static dbus_bool_t bus_register_policy_kdbus(const char* name, int fd)
{
	struct kdbus_cmd_policy *cmd_policy;
	struct kdbus_policy *policy;
	int size = 0xffff;

	cmd_policy = alloca(size);
	memset(cmd_policy, 0, size);

	policy = (struct kdbus_policy *) cmd_policy->policies;
	cmd_policy->size = offsetof(struct kdbus_cmd_policy, policies);

	policy = make_policy_name(name);
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_USER, KDBUS_POLICY_OWN, getuid());
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_RECV, 0);
	append_policy(cmd_policy, policy, size);

	policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_SEND, 0);
	append_policy(cmd_policy, policy, size);

	if (ioctl(fd, KDBUS_CMD_EP_POLICY_SET, cmd_policy) < 0)
	{
		_dbus_verbose ("Error setting policy: %m, %d", errno);
		return FALSE;
	}

	_dbus_verbose("Policy %s set correctly\n", name);
	return TRUE;
}

/**
 * Kdbus part of dbus_bus_register.
 * Shouldn't be used separately because it needs to be surrounded
 * by other functions as it is done in dbus_bus_register.
 *
 * @param name place to store unique name given by bus
 * @param connection the connection
 * @param error place to store errors
 * @returns #TRUE on success
 */
static dbus_bool_t bus_register_kdbus(char* name, DBusTransportSocket* transportS)
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
 * kdbus version of dbus_bus_request_name.
 *
 * Asks the bus to assign the given name to this connection.
 *
 * Use same flags as original dbus version with one exception below.
 * Result flag #DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER is currently
 * never returned by kdbus, instead DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
 * is returned by kdbus.
 *
 * @param connection the connection
 * @param name the name to request
 * @param flags flags
 * @param error location to store the error
 * @returns a result code, -1 if error is set
 */
static int bus_request_name_kdbus(int fd, const char *name, const uint64_t flags)
{
	struct kdbus_cmd_name *cmd_name;

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

	_dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->conn_flags);

	if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name))
	{
		_dbus_verbose ("error acquiring name '%s': %m, %d", name, errno);
		if(errno == EEXIST)
			return DBUS_REQUEST_NAME_REPLY_EXISTS;
		return -1;
	}

	_dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->conn_flags);

	if(cmd_name->conn_flags & KDBUS_NAME_IN_QUEUE)
		return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
	else
		return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
	/*todo now 1 code is never returned -  DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
	 * because kdbus never returns it now
	 */
}

/**
 * Seeks key in rule string, and duplicates value of the key into pValue.
 * If value is "org.freedesktop.DBus" it is indicated by returning -1, because it
 * needs to be handled in different manner.
 * Value is duplicated from rule string to newly allocated memory pointe by pValue,
 * so it must be freed after use.
 *
 * @param rule rule to look through
 * @param key key to look for
 * @param pValue pointer to value of the key found
 * @return length of the value string, 0 means not found, -1 means "org.freedesktop.DBus"
 */
static int parse_match_key(const char *rule, const char* key, char** pValue)
{
	const char* pBegin;
	const char* pValueEnd;
	int value_length = 0;

	pBegin = strstr(rule, key);
	if(pBegin)
	{
		pBegin += strlen(key);
		pValueEnd = strchr(pBegin, '\'');
		if(pValueEnd)
		{
			value_length = pValueEnd - pBegin;
			*pValue = strndup(pBegin, value_length);
			if(*pValue)
			{
				if(strcmp(*pValue, "org.freedesktop.DBus") == 0)
					value_length = -1;
				_dbus_verbose ("found for key: %s value:'%s'\n", key, *pValue);
			}
		}
	}
	return value_length;
}

/**
 * Adds a match rule to match broadcast messages going through the message bus.
 * Do no affect messages addressed directly.
 *
 * The "rule" argument is the string form of a match rule.
 *
 * In kdbus function do not blocks.
 *
 * Upper function returns nothing because of blocking issues
 * so there is no point to return true or false here.
 *
 * Only part of the dbus's matching capabilities is implemented in kdbus now, because of different mechanism.
 * Current mapping:
 * interface match key mapped to bloom
 * sender match key mapped to src_name
 * also handled org.freedesktop.dbus members: NameOwnerChanged, NameLost, NameAcquired
 *
 * @param connection connection to the message bus
 * @param rule textual form of match rule
 * @param error location to store any errors - may be NULL
 */
static dbus_bool_t dbus_bus_add_match_kdbus (DBusTransportSocket* transportS, const char *rule)
{
	struct kdbus_cmd_match* pCmd_match;
	struct kdbus_item *pItem;
	__u64 src_id = KDBUS_MATCH_SRC_ID_ANY;
	uint64_t size;
	unsigned int kernel_item = 0;
	int name_size;
	char* pName = NULL;
	char* pInterface = NULL;
	dbus_bool_t ret_value = FALSE;

	/*parsing rule and calculating size of command*/
	size = sizeof(struct kdbus_cmd_match);

	if(strstr(rule, "member='NameOwnerChanged'"))
	{
		kernel_item = ~0;
		size += KDBUS_ITEM_SIZE(1)*3 + KDBUS_ITEM_SIZE(sizeof(__u64))*2;  /*std DBus: 3 name related items plus 2 id related items*/
	}
	else if(strstr(rule, "member='NameChanged'"))
	{
		kernel_item = KDBUS_MATCH_NAME_CHANGE;
		size += KDBUS_ITEM_SIZE(1);
	}
	else if(strstr(rule, "member='NameLost'"))
	{
		kernel_item = KDBUS_MATCH_NAME_REMOVE;
		size += KDBUS_ITEM_SIZE(1);
	}
	else if(strstr(rule, "member='NameAcquired'"))
	{
		kernel_item = KDBUS_MATCH_NAME_ADD;
		size += KDBUS_ITEM_SIZE(1);
	}

	name_size = parse_match_key(rule, "interface='", &pInterface);
	if((name_size == -1) && (kernel_item == 0))   //means org.freedesktop.DBus without specified member
	{
		kernel_item = ~0;
		size += KDBUS_ITEM_SIZE(1)*3 + KDBUS_ITEM_SIZE(sizeof(__u64))*2;  /* 3 above name related items plus 2 id related items*/
	}
	else if(name_size > 0)   		/*actual size is not important for interface because bloom size is defined by bus*/
		size += KDBUS_PART_HEADER_SIZE + transportS->bloom_size;

	name_size = parse_match_key(rule, "sender='", &pName);
	if((name_size == -1) && (kernel_item == 0))  //means org.freedesktop.DBus without specified name - same as interface few line above
	{
		kernel_item = ~0;
		size += KDBUS_ITEM_SIZE(1)*3 + KDBUS_ITEM_SIZE(sizeof(__u64))*2; /* 3 above	name related items plus 2 id related items*/
	}
	else if(name_size > 0)
	{
		if(!strncmp(pName, ":1.", 3)) /*if name is unique name it must be converted to unique id*/
		{
			src_id = strtoull(&pName[3], NULL, 10);
			free(pName);
			pName = NULL;
		}
		else
			size += KDBUS_ITEM_SIZE(name_size + 1);  //well known name
	}

	pCmd_match = alloca(size);
	if(pCmd_match == NULL)
		goto out;

	pCmd_match->id = 0;
	pCmd_match->size = size;
	pCmd_match->cookie = strtoull(dbus_bus_get_unique_name(transportS->base.connection), NULL , 10);

	pItem = pCmd_match->items;
	if(kernel_item == ~0)  //all signals from kernel
	{
		pCmd_match->src_id = 0;
		pItem->type = KDBUS_MATCH_NAME_CHANGE;
		pItem->size = KDBUS_PART_HEADER_SIZE + 1;
		pItem = KDBUS_PART_NEXT(pItem);
		pItem->type = KDBUS_MATCH_NAME_ADD;
		pItem->size = KDBUS_PART_HEADER_SIZE + 1;
		pItem = KDBUS_PART_NEXT(pItem);
		pItem->type = KDBUS_MATCH_NAME_REMOVE;
		pItem->size = KDBUS_PART_HEADER_SIZE + 1;
		pItem = KDBUS_PART_NEXT(pItem);
		pItem->type = KDBUS_MATCH_ID_ADD;
		pItem->size = KDBUS_PART_HEADER_SIZE + sizeof(__u64);
		pItem = KDBUS_PART_NEXT(pItem);
		pItem->type = KDBUS_MATCH_ID_REMOVE;
		pItem->size = KDBUS_PART_HEADER_SIZE + sizeof(__u64);
	}
	else if(kernel_item) //only one item
	{
		pCmd_match->src_id = 0;
		pItem->type = kernel_item;
		pItem->size = KDBUS_PART_HEADER_SIZE + 1;
	}
	else
	{
		pCmd_match->src_id = src_id;
		if(pName)
		{
			pItem->type = KDBUS_MATCH_SRC_NAME;
			pItem->size = KDBUS_PART_HEADER_SIZE + name_size + 1;
			strcpy(pItem->str, pName);
			pItem = KDBUS_PART_NEXT(pItem);
		}

		if(pInterface)
		{
			pItem->type = KDBUS_MATCH_BLOOM;
			pItem->size = KDBUS_PART_HEADER_SIZE + transportS->bloom_size;
			strncpy(pItem->data, pInterface, transportS->bloom_size);
		}
	}

	if(ioctl(transportS->fd, KDBUS_CMD_MATCH_ADD, pCmd_match))
		_dbus_verbose("Failed adding match bus rule %s,\nerror: %d, %m\n", rule, errno);
	else
	{
		_dbus_verbose("Added match bus rule %s\n", rule);
		ret_value = TRUE;
	}

out:
	if(pName)
		free(pName);
	if(pInterface)
		free(pInterface);
	return ret_value;
}

/**
 * Opposing to dbus, in kdbus removes all match rules with given
 * cookie, which now is equal to uniqe id.
 *
 * In kdbus this function will not block
 *
 * @param connection connection to the message bus
 * @param error location to store any errors - may be NULL
 */
static dbus_bool_t dbus_bus_remove_match_kdbus (DBusTransportSocket* transportS)
{
	struct kdbus_cmd_match __attribute__ ((__aligned__(8))) cmd;

	cmd.cookie = strtoull(dbus_bus_get_unique_name(transportS->base.connection), NULL , 10);
	cmd.id = cmd.cookie;
	cmd.size = sizeof(struct kdbus_cmd_match);

	if(ioctl(transportS->fd, KDBUS_CMD_MATCH_ADD, &cmd))
	{
		_dbus_verbose("Failed removing match rule; error: %d, %m\n", errno);
		return FALSE;
	}
	else
	{
		_dbus_verbose("Match rule removed correctly.\n");
		return TRUE;
	}
}

/**
 * Handles messages sent to bus daemon - "org.freedesktop.DBus" and translates them to appropriate
 * kdbus ioctl commands. Than translate kdbus reply into dbus message and put it into recived messages queue.
 *
 * !!! Not all methods are handled !!! Doubt if it is even possible.
 * If method is not handled, returns error reply org.freedesktop.DBus.Error.UnknownMethod
 *
 * Handled methods:
 * - GetNameOwner
 * - NameHasOwner
 * - ListNames
 *
 * Not handled methods:
 * - ListActivatableNames
 * - StartServiceByName
 * - UpdateActivationEnvironment
 * - GetConnectionUnixUser
 * - GetId
 */
static int emulateOrgFreedesktopDBus(DBusTransport *transport, DBusMessage *message)
{
	int inter_ret;
	struct nameInfo info;
	int ret_value = -1;

	if(!strcmp(dbus_message_get_member(message), "Hello"))
	{
		char* sender = NULL;
		char* name = NULL;

		name = malloc(snprintf(name, 0, "%llu", ULLONG_MAX) + 1);
		if(name == NULL)
			return -1;
		if(!bus_register_kdbus(name, (DBusTransportSocket*)transport))
			goto outH1;
		if(!bus_register_policy_kdbus(name, ((DBusTransportSocket*)transport)->fd))
			goto outH1;

		sender = malloc (strlen(name) + 4);
		if(!sender)
			goto outH1;
		sprintf(sender, ":1.%s", name);
		((DBusTransportSocket*)transport)->sender = sender;

		if(!reply_1_data(message, DBUS_TYPE_STRING, &name, transport->connection))
			return 0;  //todo why we cannot free name after sending reply?
		else
			free(sender);

	outH1:
		free(name);
	}
	else if(!strcmp(dbus_message_get_member(message), "RequestName"))
	{
		char* name;
		int flags;
		int result;

		if(!dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_UINT32, &flags, DBUS_TYPE_INVALID))
			return -1;
		if(!bus_register_policy_kdbus(name, ((DBusTransportSocket*)transport)->fd))
			return -1;

		result = bus_request_name_kdbus(((DBusTransportSocket*)transport)->fd, name, flags);
		return reply_1_data(message, DBUS_TYPE_UINT32, &result, transport->connection);
	}
	else if(!strcmp(dbus_message_get_member(message), "AddMatch"))
	{
		char* rule;

		if(!dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &rule, DBUS_TYPE_INVALID))
			return -1;

		if(!dbus_bus_add_match_kdbus((DBusTransportSocket*)transport, rule))
			return -1;

		return reply_ack(message,transport->connection);
	}
	else if(!strcmp(dbus_message_get_member(message), "RemoveMatch"))
	{
		if(!dbus_bus_remove_match_kdbus((DBusTransportSocket*)transport))
			return -1;
		return reply_ack(message, transport->connection);
	}
	else if(!strcmp(dbus_message_get_member(message), "GetNameOwner"))  //returns id of the well known name
	{
		char* name = NULL;

		dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		inter_ret = kdbus_NameQuery(name, ((DBusTransportSocket*)transport)->fd, &info);
		if(inter_ret == 0) //unique id of the name
		{
			char unique_name[(unsigned int)(snprintf(name, 0, "%llu", ULLONG_MAX) + sizeof(":1."))];
			const char* pString = unique_name;

			sprintf(unique_name, ":1.%llu", (unsigned long long int)info.uniqueId);
			_dbus_verbose("Unique name discovered:%s\n", unique_name);
			ret_value = reply_1_data(message, DBUS_TYPE_STRING, &pString, transport->connection);
		}
		else if(inter_ret == -ENOENT)  //name has no owner
			return reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Could not get owner of name '%s': no such name", name, message, transport->connection);
		else
		{
			_dbus_verbose("kdbus error sending name query: err %d (%m)\n", errno);
			ret_value = reply_with_error(DBUS_ERROR_FAILED, "Could not determine unique name for '%s'", name, message, transport->connection);
		}
	}
	else if(!strcmp(dbus_message_get_member(message), "NameHasOwner"))   //returns if name is currently registered on the bus
	{
		char* name = NULL;
		dbus_bool_t result;

		dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		inter_ret = kdbus_NameQuery(name, ((DBusTransportSocket*)transport)->fd, &info);
		if((inter_ret == 0) || (inter_ret == -ENOENT))
		{
			result = (inter_ret == 0) ? TRUE : FALSE;
			ret_value = reply_1_data(message, DBUS_TYPE_BOOLEAN, &result, transport->connection);
		}
		else
		{
			_dbus_verbose("kdbus error checking if name exists: err %d (%m)\n", errno);
			ret_value = reply_with_error(DBUS_ERROR_FAILED, "Could not determine whether name '%s' exists", name, message, transport->connection);
		}
	}
	else if(!strcmp(dbus_message_get_member(message), "GetConnectionUnixUser"))
	{
		char* name = NULL;

		dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		inter_ret = kdbus_NameQuery(name, ((DBusTransportSocket*)transport)->fd, &info);
		if(inter_ret == 0) //name found
		{
			_dbus_verbose("User id:%llu\n", (unsigned long long) info.userId);
			ret_value = reply_1_data(message, DBUS_TYPE_UINT32, &info.userId, transport->connection);
		}
		else if(inter_ret == -ENOENT)  //name has no owner
			return reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Could not get UID of name '%s': no such name", name, message, transport->connection);
		else
		{
			_dbus_verbose("kdbus error determining UID: err %d (%m)\n", errno);
			ret_value = reply_with_error(DBUS_ERROR_FAILED, "Could not determine UID for '%s'", name, message, transport->connection);
		}
	}
	else if(!strcmp(dbus_message_get_member(message), "GetConnectionUnixProcessID"))
	{
		char* name = NULL;

		dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		inter_ret = kdbus_NameQuery(name, ((DBusTransportSocket*)transport)->fd, &info);
		if(inter_ret == 0) //name found
			ret_value = reply_1_data(message, DBUS_TYPE_UINT32, &info.processId, transport->connection);
		else if(inter_ret == -ENOENT)  //name has no owner
			return reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Could not get PID of name '%s': no such name", name, message, transport->connection);
		else
		{
			_dbus_verbose("kdbus error determining PID: err %d (%m)\n", errno);
			ret_value = reply_with_error(DBUS_ERROR_UNIX_PROCESS_ID_UNKNOWN,"Could not determine PID for '%s'", name, message, transport->connection);
		}
	}
	else if(!strcmp(dbus_message_get_member(message), "ListNames"))  //return all well known names on he bus
	{
		struct kdbus_cmd_names* pCmd;
		uint64_t cmd_size;

		cmd_size = sizeof(struct kdbus_cmd_names) + KDBUS_ITEM_SIZE(1);
		pCmd = malloc(cmd_size);
		if(pCmd == NULL)
			goto out;
		pCmd->size = cmd_size;

  again:
		cmd_size = 0;
		if(ioctl(((DBusTransportSocket*)transport)->fd, KDBUS_CMD_NAME_LIST, pCmd))
		{
			if(errno == EINTR)
				goto again;
			if(errno == ENOBUFS)			//buffer to small to put all names into it
				cmd_size = pCmd->size;		//here kernel tells how much memory it needs
			else
			{
				_dbus_verbose("kdbus error asking for name list: err %d (%m)\n",errno);
				goto out;
			}
		}
		if(cmd_size)  //kernel needs more memory
		{
			pCmd = realloc(pCmd, cmd_size);  //prepare memory
			if(pCmd == NULL)
				return -1;
			goto again;						//and try again
		}
		else
		{
			DBusMessage *reply;
			DBusMessageIter iter, sub;
			struct kdbus_cmd_name* pCmd_name;
			char* pName;

			reply = dbus_message_new_method_return(message);
			if(reply == NULL)
				goto out;
			dbus_message_set_sender(reply, DBUS_SERVICE_DBUS);
			dbus_message_iter_init_append(reply, &iter);
			if (!dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &sub))
			{
				dbus_message_unref(reply);
				goto out;
			}
			for (pCmd_name = pCmd->names; (uint8_t *)(pCmd_name) < (uint8_t *)(pCmd) + pCmd->size; pCmd_name = KDBUS_PART_NEXT(pCmd_name))
			{
				pName = pCmd_name->name;
				if (!dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &pName))
				{
					dbus_message_unref(reply);
					goto out;
				}
			}

			if (!dbus_message_iter_close_container (&iter, &sub))
			{
				dbus_message_unref (reply);
				goto out;
			}

			if(add_message_to_received(reply, transport->connection))
				ret_value = 0;
		}
out:
		if(pCmd)
			free(pCmd);
		return ret_value;
	}
	else if(!strcmp(dbus_message_get_member(message), "GetId"))
	{
		char* path;
		char uuid[DBUS_UUID_LENGTH_BYTES];
		struct stat stats;
		MD5_CTX md5;
		DBusString binary, encoded;

		path = &transport->address[11]; //start of kdbus bus path
		if(stat(path, &stats) < -1)
		{
			_dbus_verbose("kdbus error reading stats of bus: err %d (%m)\n", errno);
			return reply_with_error(DBUS_ERROR_FAILED, "Could not determine bus '%s' uuid", path, message, transport->connection);
		}

		MD5_Init(&md5);
        MD5_Update(&md5, path, strlen(path));
        MD5_Update(&md5, &stats.st_ctim.tv_sec, sizeof(stats.st_ctim.tv_sec));
		MD5_Final(uuid, &md5);

		if(!_dbus_string_init (&encoded))
			goto outgid;
		_dbus_string_init_const_len (&binary, uuid, DBUS_UUID_LENGTH_BYTES);
		if(!_dbus_string_hex_encode (&binary, 0, &encoded, _dbus_string_get_length (&encoded)))
			goto outb;
		path = (char*)_dbus_string_get_const_data (&encoded);
		ret_value = reply_1_data(message, DBUS_TYPE_STRING, &path, transport->connection);

	outb:
		_dbus_string_free(&binary);
		_dbus_string_free(&encoded);
	outgid:
		return ret_value;
	}
	else if(!strcmp(dbus_message_get_member(message), "GetAdtAuditSessionData"))
	{
		char* name = NULL;

		dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		return reply_with_error(DBUS_ERROR_ADT_AUDIT_DATA_UNKNOWN, "Could not determine audit session data for '%s'", name, message, transport->connection);
	}
	else if(!strcmp(dbus_message_get_member(message), "GetConnectionSELinuxSecurityContext"))
	{
		char* name = NULL;

		dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
		inter_ret = kdbus_NameQuery(name, ((DBusTransportSocket*)transport)->fd, &info);
		if(inter_ret == -ENOENT)  //name has no owner
			return reply_with_error(DBUS_ERROR_NAME_HAS_NO_OWNER, "Could not get security context of name '%s': no such name", name, message, transport->connection);
		else if(inter_ret < 0)
			return reply_with_error(DBUS_ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN, "Could not determine security context for '%s'", name, message, transport->connection);
		else
		{
			DBusMessage *reply;

			reply = dbus_message_new_method_return(message);
			if(reply != NULL)
			{
				dbus_message_set_sender(reply, DBUS_SERVICE_DBUS);
				if (!dbus_message_append_args (reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &info.sec_label, info.sec_label_len, DBUS_TYPE_INVALID))
					dbus_message_unref(reply);
				else if(add_message_to_received(reply, transport->connection))
					ret_value = 0;
			}
		}
	}
	else
		return 1;  //send to daemon
//		return reply_with_error(DBUS_ERROR_UNKNOWN_METHOD, NULL, (char*)dbus_message_get_member(message), message, transport->connection);
/*	else if(!strcmp(dbus_message_get_member(message), "ListActivatableNames"))  //todo
	{

	}
	else if(!strcmp(dbus_message_get_member(message), "StartServiceByName"))
	{

	}
	else if(!strcmp(dbus_message_get_member(message), "UpdateActivationEnvironment"))
	{

	}
	else if(!strcmp(dbus_message_get_member(message), "ReloadConfig"))
	{

	}
	*/

	if(info.sec_label)
		free(info.sec_label);
	return ret_value;
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
 * Decodes kdbus message in order to extract dbus message and put it into data and fds.
 * Also captures and decodes kdbus error messages and kdbus kernel broadcasts and converts
 * all of them into dbus messages.
 *
 * @param msg kdbus message
 * @param data place to copy dbus message to
 * @param socket_transport transport
 * @param fds place to store file descriptors received
 * @param n_fds place to store quantity of file descriptor
 * @return number of dbus message's bytes received or -1 on error
 */
static int kdbus_decode_msg(const struct kdbus_msg* msg, char *data, DBusTransportSocket* socket_transport, int* fds, int* n_fds)
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
				memcpy(data, (char *)socket_transport->kdbus_mmap_ptr + item->vec.offset, item->vec.size);
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
static int kdbus_read_message(DBusTransportSocket *socket_transport, DBusString *buffer, int* fds, int* n_fds)
{
	int ret_size;
	uint64_t __attribute__ ((__aligned__(8))) offset;
	struct kdbus_msg *msg;
	char *data;
	int start;

	start = _dbus_string_get_length (buffer);
	if (!_dbus_string_lengthen (buffer, socket_transport->max_bytes_read_per_iteration))
	{
		errno = ENOMEM;
	    return -1;
	}
	data = _dbus_string_get_data_len (buffer, start, socket_transport->max_bytes_read_per_iteration);

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

	ret_size = kdbus_decode_msg(msg, data, socket_transport, fds, n_fds);

	if(ret_size == -1) /* error */
	{
		_dbus_string_set_length (buffer, start);
		return -1;
	}
	else
		_dbus_string_set_length (buffer, start + ret_size);
	

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

#ifdef DBUS_AUTHENTICATION
  if (_dbus_transport_get_is_authenticated (transport))
#endif
    needed = _dbus_connection_has_messages_to_send_unlocked (transport->connection);
#ifdef DBUS_AUTHENTICATION
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
#endif
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

#ifdef DBUS_AUTHENTICATION
  if (_dbus_transport_get_is_authenticated (transport))
#endif
    need_read_watch =
      (_dbus_counter_get_size_value (transport->live_messages) < transport->max_live_messages_size) &&
      (_dbus_counter_get_unix_fd_value (transport->live_messages) < transport->max_live_messages_unix_fds);
#ifdef DBUS_AUTHENTICATION
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
#endif

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

#ifdef DBUS_AUTHENTICATION
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

  bytes_read = kdbus_read_message(socket_transport, buffer);

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
#endif

/* returns false on oom */
static dbus_bool_t
do_writing (DBusTransport *transport)
{
	DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
	dbus_bool_t oom;

#ifdef DBUS_AUTHENTICATION
	/* No messages without authentication! */
	if (!_dbus_transport_get_is_authenticated (transport))
    {
		_dbus_verbose ("Not authenticated, not writing anything\n");
		return TRUE;
    }
#endif

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
		dbus_message_unlock(message);
	    dbus_message_set_sender(message, socket_transport->sender);
		dbus_message_lock (message);
		_dbus_message_get_network_data (message, &header, &body);
		total_bytes_to_write = _dbus_string_get_length(header) + _dbus_string_get_length(body);
		pDestination = dbus_message_get_destination(message);

		if(pDestination)
		{
			if(!strcmp(pDestination, "org.freedesktop.DBus"))
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
		if (_dbus_auth_needs_encoding (transport->auth))
        {
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
			if(total_bytes_to_write > socket_transport->max_bytes_written_per_iteration)
				return -E2BIG;

			bytes_written = kdbus_write_msg(socket_transport, message, TRUE);
        }
		else
		{
			if(total_bytes_to_write > socket_transport->max_bytes_written_per_iteration)
				return -E2BIG;

			bytes_written = kdbus_write_msg(socket_transport, message, FALSE);
		}

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
	return TRUE;
}

/* returns false on out-of-memory */
static dbus_bool_t
do_reading (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;
  DBusString *buffer;
  int bytes_read;
  dbus_bool_t oom = FALSE;
  int *fds, n_fds;

  _dbus_verbose ("fd = %d\n",socket_transport->fd);

#ifdef DBUS_AUTHENTICATION
  /* No messages without authentication! */
  if (!_dbus_transport_get_is_authenticated (transport))
    return TRUE;
#endif

 again:

  /* See if we've exceeded max messages and need to disable reading */
  check_read_watch (transport);

  _dbus_assert (socket_transport->read_watch != NULL ||
                transport->disconnected);

  if (transport->disconnected)
    goto out;

  if (!dbus_watch_get_enabled (socket_transport->read_watch))
    return TRUE;

  if (!_dbus_message_loader_get_unix_fds(transport->loader, &fds, &n_fds))
  {
      _dbus_verbose ("Out of memory reading file descriptors\n");
      oom = TRUE;
      goto out;
  }
  _dbus_message_loader_get_buffer (transport->loader, &buffer);

  if (_dbus_auth_needs_decoding (transport->auth))
  {
	  bytes_read = kdbus_read_message(socket_transport,  &socket_transport->encoded_incoming, fds, &n_fds);

      _dbus_assert (_dbus_string_get_length (&socket_transport->encoded_incoming) == bytes_read);

      if (bytes_read > 0)
      {
          if (!_dbus_auth_decode_data (transport->auth,
                                       &socket_transport->encoded_incoming,
                                       buffer))
          {
              _dbus_verbose ("Out of memory decoding incoming data\n");
              _dbus_message_loader_return_buffer (transport->loader,
                                              buffer,
                                              _dbus_string_get_length (buffer));
              oom = TRUE;
              goto out;
          }

          _dbus_string_set_length (&socket_transport->encoded_incoming, 0);
          _dbus_string_compact (&socket_transport->encoded_incoming, 2048);
      }
  }
  else
	  bytes_read = kdbus_read_message(socket_transport, buffer, fds, &n_fds);

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

static dbus_bool_t
unix_error_with_read_to_come (DBusTransport *itransport,
                              DBusWatch     *watch,
                              unsigned int   flags)
{
   DBusTransportSocket *transport = (DBusTransportSocket *) itransport;

   if (!((flags & DBUS_WATCH_HANGUP) || (flags & DBUS_WATCH_ERROR)))
      return FALSE;

  /* If we have a read watch enabled ...
     we -might have data incoming ... => handle the HANGUP there */
   if (watch != transport->read_watch && _dbus_watch_get_enabled (transport->read_watch))
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
#ifdef DBUS_AUTHENTICATION
      dbus_bool_t auth_finished;
#endif
#if 1
      _dbus_verbose ("handling read watch %p flags = %x\n",
                     watch, flags);
#endif
#ifdef DBUS_AUTHENTICATION
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
#endif
	  if (!do_reading (transport))
	    {
	      _dbus_verbose ("no memory to read\n");
	      return FALSE;
	    }
#ifdef DBUS_AUTHENTICATION
	}
      else
        {
          _dbus_verbose ("Not reading anything since we just completed the authentication\n");
        }
#endif
    }
  else if (watch == socket_transport->write_watch &&
           (flags & DBUS_WATCH_WRITABLE))
    {
#if 1
      _dbus_verbose ("handling write watch, have_outgoing_messages = %d\n",
                     _dbus_connection_has_messages_to_send_unlocked (transport->connection));
#endif
#ifdef DBUS_AUTHENTICATION
      if (!do_authentication (transport, FALSE, TRUE, NULL))
        return FALSE;
#endif
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
kdbus_connection_set (DBusTransport *transport)
{
  DBusTransportSocket *socket_transport = (DBusTransportSocket*) transport;

  dbus_connection_set_is_authenticated(transport->connection); //todo remove when authentication will work

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

   if (_dbus_transport_peek_is_authenticated (transport))
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
#ifdef DBUS_AUTHENTICATION
              dbus_bool_t authentication_completed;
#endif

            _dbus_verbose ("in iteration, need_read=%d need_write=%d\n",
                             need_read, need_write);
#ifdef DBUS_AUTHENTICATION
              do_authentication (transport, need_read, need_write,
				 &authentication_completed);

	      /* See comment in socket_handle_watch. */
	      if (authentication_completed)
                goto out;
#endif
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
  kdbus_connection_set,
  kdbus_do_iteration,
  socket_live_messages_changed,
  socket_get_socket_fd
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
_dbus_transport_new_for_socket_kdbus (int	fd,
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
                                  NULL, address))
    goto failed_4;

#ifdef DBUS_AUTHENTICATION
#ifdef HAVE_UNIX_FD_PASSING
  _dbus_auth_set_unix_fd_possible(socket_transport->base.auth, _dbus_socket_can_pass_unix_fd(fd));
#endif
#endif

  socket_transport->fd = fd;
  socket_transport->message_bytes_written = 0;

  /* These values should probably be tunable or something. */
  socket_transport->max_bytes_read_per_iteration = DBUS_MAXIMUM_MESSAGE_LENGTH;
  socket_transport->max_bytes_written_per_iteration = DBUS_MAXIMUM_MESSAGE_LENGTH;

  socket_transport->kdbus_mmap_ptr = NULL;
  socket_transport->memfd = -1;
  
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

	transport = _dbus_transport_new_for_socket_kdbus (fd, &address);
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
