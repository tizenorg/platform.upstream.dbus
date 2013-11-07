/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-d.c  kdbus related daemon functions
 *
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

#include <dbus/dbus-connection-internal.h>
#include "kdbus-d.h"
#include <dbus/kdbus.h>
#include <dbus/dbus-bus.h>
#include "dispatch.h"
#include <dbus/kdbus-common.h>
#include <dbus/dbus-transport.h>
#include <dbus/dbus-transport-kdbus.h>
#include "connection.h"
#include "activation.h"
#include "services.h"
#include <dbus/dbus-connection.h>

#include <utils.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/*
 * Converts string with unique name into __u64 id number. If the name is not unique, sets error.
 */
__u64 sender_name_to_id(const char* name, DBusError* error)
{
	__u64 sender_id = 0;

	if(!strncmp(name, ":1.", 3)) /*if name is unique name it must be converted to unique id*/
		sender_id = strtoull(&name[3], NULL, 10);
	else
		dbus_set_error (error, DBUS_ERROR_INVALID_ARGS, "Could not convert sender of the message into kdbus unique id");

	return sender_id;
}

/**
 * Seeks key in rule string, and duplicates value of the key into pValue.
 * Because of the duplication, pValue must be freed after use.
 *
 * @param rule rule to look through
 * @param key key to look for
 * @param pValue pointer to value of the key found
 * @return length of the value string, 0 means not found
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
        _dbus_verbose ("found for key: %s value:'%s'\n", key, *pValue);
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
 * Only part of the dbus's matching capabilities is implemented in kdbus now, because of different mechanism.
 * Current mapping:
 * interface match key mapped to bloom
 * sender match key mapped to src_name
 *
 * @param transport transport
 * @param id id of connection for which the rule is to be added
 * @param rule textual form of match rule
  */
dbus_bool_t add_match_kdbus (DBusTransport* transport, __u64 id, const char *rule)
{
  struct kdbus_cmd_match* pCmd_match;
  struct kdbus_item *pItem;
  __u64 src_id = KDBUS_MATCH_SRC_ID_ANY;
  uint64_t size;
  int name_size;
  char* pName = NULL;
  char* pInterface = NULL;
  dbus_bool_t ret_value = FALSE;
  int fd;
  __u64 bloom_size;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return FALSE;

  bloom_size = dbus_transport_get_bloom_size(transport);

  /*parsing rule and calculating size of command*/
  size = sizeof(struct kdbus_cmd_match);
  if(parse_match_key(rule, "interface='", &pInterface))       /*actual size is not important for interface because bloom size is defined by bus*/
    size += KDBUS_PART_HEADER_SIZE + bloom_size;
  name_size = parse_match_key(rule, "sender='", &pName);
  if(name_size)
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

  pCmd_match->id = id;
  pCmd_match->cookie = id;
  pCmd_match->size = size;
  pCmd_match->src_id = src_id;

  pItem = pCmd_match->items;
  if(pName)
  {
    pItem->type = KDBUS_MATCH_SRC_NAME;
    pItem->size = KDBUS_PART_HEADER_SIZE + name_size + 1;
    memcpy(pItem->str, pName, strlen(pName) + 1);
    pItem = KDBUS_PART_NEXT(pItem);
  }
  if(pInterface)
  {
    pItem->type = KDBUS_MATCH_BLOOM;
    pItem->size = KDBUS_PART_HEADER_SIZE + bloom_size;
    strncpy(pItem->data, pInterface, bloom_size);
  }

  if(ioctl(fd, KDBUS_CMD_MATCH_ADD, pCmd_match))
    _dbus_verbose("Failed adding match bus rule %s,\nerror: %d, %m\n", rule, errno);
  else
  {
    _dbus_verbose("Added match bus rule %s for id:%llu\n", rule, (unsigned long long)id);
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
 * cookie, which in this implementation is equal to uniqe id.
 *
 * @param transport transport
 * @param id connection id for which rules are to be removed
 */
dbus_bool_t remove_match_kdbus (DBusTransport* transport, __u64 id)
{
  struct kdbus_cmd_match __attribute__ ((__aligned__(8))) cmd;
  int fd;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return FALSE;

  cmd.cookie = id;
  cmd.id = id;
  cmd.size = sizeof(struct kdbus_cmd_match);

  if(ioctl(fd, KDBUS_CMD_MATCH_REMOVE, &cmd))
  {
    _dbus_verbose("Failed removing match rule for id: %llu; error: %d, %m\n", (unsigned long long)id, errno);
    return FALSE;
  }
  else
  {
    _dbus_verbose("Match rule removed correctly.\n");
    return TRUE;
  }
}

/**
 * Performs kdbus query of id of the given name
 *
 * @param name name to query for
 * @param transport transport
 * @param pInfo nameInfo structure address to store info about the name
 * @return 0 on success, -errno if failed
 */
int kdbus_NameQuery(const char* name, DBusTransport* transport, struct nameInfo* pInfo)
{
  struct kdbus_cmd_name_info *msg;
  struct kdbus_item *item;
  uint64_t size;
  int ret;
  uint64_t item_size;
  int fd;

  pInfo->sec_label_len = 0;
  pInfo->sec_label = NULL;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return -EPERM;

  item_size = KDBUS_PART_HEADER_SIZE + strlen(name) + 1;
  item_size = (item_size < 56) ? 56 : item_size;  //at least 56 bytes are needed by kernel to place info about name, otherwise error
  size = sizeof(struct kdbus_cmd_name_info) + item_size;

  msg = malloc(size);
  if (!msg)
  {
    _dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
    return -errno;
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
  memcpy(item->str, name, strlen(name) + 1);

  again:
  ret = ioctl(fd, KDBUS_CMD_NAME_QUERY, msg);
  if (ret < 0)
  {
    if(errno == EINTR)
      goto again;
    if(errno == EAGAIN)
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
    item = msg->items;
    while((uint8_t *)(item) < (uint8_t *)(msg) + msg->size)
    {
      if(item->type == KDBUS_NAME_INFO_ITEM_SECLABEL)
      {
          pInfo->sec_label_len = item->size - KDBUS_PART_HEADER_SIZE - 1;
        if(pInfo->sec_label_len != 0)
        {
          pInfo->sec_label = malloc(pInfo->sec_label_len);
          if(pInfo->sec_label == NULL)
            ret = -1;
          else
            memcpy(pInfo->sec_label, item->data, pInfo->sec_label_len);
        }
        break;
      }
      item = KDBUS_PART_NEXT(item);
    }
  }

  free(msg);
  return ret;
}

/*
 * Creates kdbus bus of given type.
 */
char* make_kdbus_bus(DBusBusType type, DBusError *error)
{
    struct {
        struct kdbus_cmd_bus_make head;
        uint64_t n_size;
        uint64_t n_type;
        char name[64];
    } __attribute__ ((__aligned__(8))) bus_make;

    int fdc, ret;
    char *bus;

    _dbus_verbose("Opening /dev/kdbus/control\n");
    fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
    if (fdc < 0)
    {
        _dbus_verbose("--- error %d (%m)\n", fdc);
        dbus_set_error(error, DBUS_ERROR_FAILED, "Opening /dev/kdbus/control failed: %d (%m)", fdc);
        return NULL;
    }

    memset(&bus_make, 0, sizeof(bus_make));
    bus_make.head.bloom_size = 64;
    bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;

    if(type == DBUS_BUS_SYSTEM)
        snprintf(bus_make.name, sizeof(bus_make.name), "%u-kdbus-%s", getuid(), "system");
    else if(type == DBUS_BUS_SESSION)
        snprintf(bus_make.name, sizeof(bus_make.name), "%u-kdbus", getuid());
    else
        snprintf(bus_make.name, sizeof(bus_make.name), "%u-kdbus-%u", getuid(), getpid());

    bus_make.n_type = KDBUS_MAKE_NAME;
    bus_make.n_size = KDBUS_PART_HEADER_SIZE + strlen(bus_make.name) + 1;
    bus_make.head.size = sizeof(struct kdbus_cmd_bus_make) + bus_make.n_size;

    _dbus_verbose("Creating bus '%s'\n", bus_make.name);
    ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, &bus_make);
    if (ret)
    {
        _dbus_verbose("--- error %d (%m)\n", ret);
        dbus_set_error(error, DBUS_ERROR_FAILED, "Creating bus '%s' failed: %d (%m)", bus_make.name, fdc);
        return NULL;
    }

    if (asprintf(&bus, "kdbus:path=/dev/kdbus/%s/bus", bus_make.name) < 0)
    {
        BUS_SET_OOM (error);
        return NULL;
    }

    _dbus_verbose("Return value '%s'\n", bus);
	return bus;
}

/*
 * Minimal server init needed by context to go further.
 */
DBusServer* empty_server_init(char* address)
{
	return dbus_server_init_mini(address);
}

static dbus_bool_t add_matches_for_kdbus_broadcasts(DBusTransport* transport)
{
  struct kdbus_cmd_match* pCmd_match;
  struct kdbus_item *pItem;
  uint64_t size;
  int fd;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    {
      errno = EPERM;
      return FALSE;
    }


  size = sizeof(struct kdbus_cmd_match);
  size += KDBUS_ITEM_SIZE(1)*3 + KDBUS_ITEM_SIZE(sizeof(__u64))*2;  /*3 name related items plus 2 id related items*/

  pCmd_match = alloca(size);
  if(pCmd_match == NULL)
    {
      errno = ENOMEM;
      return FALSE;
    }

  pCmd_match->id = 1;
  pCmd_match->cookie = 1;
  pCmd_match->size = size;

  pItem = pCmd_match->items;
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

  if(ioctl(fd, KDBUS_CMD_MATCH_ADD, pCmd_match))
    {
      _dbus_verbose("Failed adding match rule for daemon, error: %d, %m\n", errno);
      return FALSE;
    }

  _dbus_verbose("Added match rule for daemon correctly.\n");
  return TRUE;
}

/*
 * Connects daemon to bus created by him and adds matches for "system" broadcasts.
 * Do not requests org.freedesktop.DBus name, because it's to early
 * (some structures of BusContext are not ready yet).
 */
DBusConnection* daemon_as_client(DBusBusType type, char* address, DBusError *error)
{
  DBusConnection* connection;

  dbus_bus_set_bus_connection_address(type, address);

  connection = dbus_bus_get_private(type, error);  /*todo possibly could be optimised by using lower functions*/
  if(connection == NULL)
    return NULL;

  if(!add_matches_for_kdbus_broadcasts(dbus_connection_get_transport(connection)))
    {
      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for daemon, %s", _dbus_strerror_from_errno ());
      goto failed;
    }

  if(dbus_error_is_set(error))
    {
      failed:
      _dbus_connection_close_possibly_shared (connection);
      dbus_connection_unref (connection);
      connection = NULL;
    }
  else
    _dbus_verbose ("Daemon connected as kdbus client.\n");

  return connection;
}

/*
 * Asks bus for org.freedesktop.DBus well-known name.
 */
dbus_bool_t register_daemon_name(DBusConnection* connection)
{
    DBusString daemon_name;
    dbus_bool_t retval = FALSE;
    BusTransaction *transaction;

    _dbus_string_init_const(&daemon_name, DBUS_SERVICE_DBUS);
    if(!register_kdbus_policy(DBUS_SERVICE_DBUS, dbus_connection_get_transport(connection), geteuid()))
      return FALSE;

    if(kdbus_request_name(connection, &daemon_name, 0, 0) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
       return FALSE;

    transaction = bus_transaction_new (bus_connection_get_context(connection));
    if (transaction == NULL)
    {
        kdbus_release_name(connection, &daemon_name, 0);
        goto out;
    }

    if(!bus_registry_ensure (bus_connection_get_registry (connection), &daemon_name, connection, 0, transaction, NULL))
    {
        kdbus_release_name(connection, &daemon_name, 0);
        goto out;
    }

    retval = TRUE;

out:
	bus_transaction_cancel_and_free(transaction);
    return retval;
}

dbus_uint32_t kdbus_request_name(DBusConnection* connection, const DBusString *service_name, dbus_uint32_t flags, __u64 sender_id)
{
	int fd;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

	return request_kdbus_name(fd, _dbus_string_get_const_data(service_name), flags, sender_id);
}

dbus_uint32_t kdbus_release_name(DBusConnection* connection, const DBusString *service_name, __u64 sender_id)
{
	int fd;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

	return release_kdbus_name(fd, _dbus_string_get_const_data(service_name), sender_id);
}

/*
 * Asks kdbus for well-known names registered on the bus
 */
dbus_bool_t kdbus_list_services (DBusConnection* connection, char ***listp, int *array_len)
{
	int fd;
	struct kdbus_cmd_names* pCmd;
	__u64 cmd_size;
	dbus_bool_t ret_val = FALSE;
	char** list;
	int list_len = 0;
	int i = 0;
	int j;

	cmd_size = sizeof(struct kdbus_cmd_names) + KDBUS_ITEM_SIZE(1);
	pCmd = malloc(cmd_size);
	if(pCmd == NULL)
		goto out;
	pCmd->size = cmd_size;

	_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd);

again:
	cmd_size = 0;
	if(ioctl(fd, KDBUS_CMD_NAME_LIST, pCmd))
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
			return FALSE;
		goto again;						//and try again
	}
	else
	{
		struct kdbus_cmd_name* pCmd_name;

		for (pCmd_name = pCmd->names; (uint8_t *)(pCmd_name) < (uint8_t *)(pCmd) + pCmd->size; pCmd_name = KDBUS_PART_NEXT(pCmd_name))
			list_len++;

		list = malloc(sizeof(char*) * (list_len + 1));
		if(list == NULL)
			goto out;

		for (pCmd_name = pCmd->names; (uint8_t *)(pCmd_name) < (uint8_t *)(pCmd) + pCmd->size; pCmd_name = KDBUS_PART_NEXT(pCmd_name))
		{
			list[i] = strdup(pCmd_name->name);
			if(list[i] == NULL)
			{
				for(j=0; j<i; j++)
					free(list[j]);
				free(list);
				goto out;
			}
			_dbus_verbose ("Name %d: %s\n", i, list[i]);
			++i;
		}
		list[i] = NULL;
	}

	*array_len = list_len;
	*listp = list;
	ret_val = TRUE;

out:
	if(pCmd)
		free(pCmd);
	return ret_val;
}

/*
 *  Register match rule in kdbus on behalf of sender of the message
 */
dbus_bool_t kdbus_add_match_rule (DBusConnection* connection, DBusMessage* message, const char* text, DBusError* error)
{
	__u64 sender_id;

	sender_id = sender_name_to_id(dbus_message_get_sender(message), error);
	if(dbus_error_is_set(error))
		return FALSE;

	if(!add_match_kdbus (dbus_connection_get_transport(connection), sender_id, text))
	{
	      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not add match for id:%d, %s",
	                      sender_id, _dbus_strerror_from_errno ());
	      return FALSE;
	}

	return TRUE;
}

/*
 *  Removes match rule in kdbus on behalf of sender of the message
 */
dbus_bool_t kdbus_remove_match (DBusConnection* connection, DBusMessage* message, DBusError* error)
{
	__u64 sender_id;

	sender_id = sender_name_to_id(dbus_message_get_sender(message), error);
	if(dbus_error_is_set(error))
		return FALSE;

	if(!remove_match_kdbus (dbus_connection_get_transport(connection), sender_id))
	{
	      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not remove match rules for id:%d", sender_id);
	      return FALSE;
	}

	return TRUE;
}

int kdbus_get_name_owner(DBusConnection* connection, const char* name, char* owner)
{
  int ret;
  struct nameInfo info;

  ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
  if(ret == 0) //unique id of the name
  {
    sprintf(owner, ":1.%llu", (unsigned long long int)info.uniqueId);
    _dbus_verbose("Unique name discovered:%s\n", owner);
  }
  else if(ret != -ENOENT)
    _dbus_verbose("kdbus error sending name query: err %d (%m)\n", errno);

  return ret;
}

/*
 *  Asks kdbus for uid of the owner of the name given in the message
 */
dbus_bool_t kdbus_get_unix_user(DBusConnection* connection, const char* name, unsigned long* uid, DBusError* error)
{
  struct nameInfo info;
  int inter_ret;
  dbus_bool_t ret = FALSE;

  inter_ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
  if(inter_ret == 0) //name found
  {
    _dbus_verbose("User id:%llu\n", (unsigned long long) info.userId);
    *uid = info.userId;
    return TRUE;
  }
  else if(inter_ret == -ENOENT)  //name has no owner
    {
      _dbus_verbose ("Name %s has no owner.\n", name);
      dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get UID of name '%s': no such name", name);
    }

  else
  {
    _dbus_verbose("kdbus error determining UID: err %d (%m)\n", errno);
    dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine UID for '%s'", name);
  }

  return ret;
}

/*
 *  Asks kdbus for pid of the owner of the name given in the message
 */
dbus_bool_t kdbus_get_connection_unix_process_id(DBusConnection* connection, const char* name, unsigned long* pid, DBusError* error)
{
	struct nameInfo info;
	int inter_ret;
	dbus_bool_t ret = FALSE;

	inter_ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
	if(inter_ret == 0) //name found
	{
		_dbus_verbose("Process id:%llu\n", (unsigned long long) info.processId);
		*pid = info.processId;
		return TRUE;
	}
	else if(inter_ret == -ENOENT)  //name has no owner
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get PID of name '%s': no such name", name);
	else
	{
		_dbus_verbose("kdbus error determining PID: err %d (%m)\n", errno);
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine PID for '%s'", name);
	}

	return ret;
}

/*
 *  Asks kdbus for selinux_security_context of the owner of the name given in the message
 */
dbus_bool_t kdbus_get_connection_unix_selinux_security_context(DBusConnection* connection, DBusMessage* message, DBusMessage* reply, DBusError* error)
{
	char* name = NULL;
	struct nameInfo info;
	int inter_ret;
	dbus_bool_t ret = FALSE;

	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);
	inter_ret = kdbus_NameQuery(name, dbus_connection_get_transport(connection), &info);
	if(inter_ret == -ENOENT)  //name has no owner
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not get security context of name '%s': no such name", name);
	else if(inter_ret < 0)
	{
		_dbus_verbose("kdbus error determining security context: err %d (%m)\n", errno);
		dbus_set_error (error, DBUS_ERROR_FAILED, "Could not determine security context for '%s'", name);
	}
	else
	{
		if (!dbus_message_append_args (reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &info.sec_label, info.sec_label_len, DBUS_TYPE_INVALID))
		{
		      _DBUS_SET_OOM (error);
		      return FALSE;
		}
		ret = TRUE;
	}

	return ret;
}

/**
 * Gets the UNIX user ID of the connection from kdbus, if known. Returns #TRUE if
 * the uid is filled in.  Always returns #FALSE on non-UNIX platforms
 * for now., though in theory someone could hook Windows to NIS or
 * something.  Always returns #FALSE prior to authenticating the
 * connection.
 *
 * The UID of is only read by bus daemon from kdbus. You can not
 * call this function from client side of the connection.
 *
 * You can ask the bus to tell you the UID of another connection though
 * if you like; this is done with dbus_bus_get_unix_user().
 *
 * @param connection the connection
 * @param uid return location for the user ID
 * @returns #TRUE if uid is filled in with a valid user ID
 */
dbus_bool_t
dbus_connection_get_unix_user (DBusConnection *connection,
                               unsigned long  *uid)
{
  _dbus_return_val_if_fail (connection != NULL, FALSE);
  _dbus_return_val_if_fail (uid != NULL, FALSE);

  if(bus_context_is_kdbus(bus_connection_get_context (connection)))
    return kdbus_get_unix_user(connection, bus_connection_get_name(connection), uid, NULL);

  return dbus_connection_get_unix_user_dbus(connection, uid);
}

/**
 * Gets the process ID of the connection if any.
 * Returns #TRUE if the pid is filled in.
 *
 * @param connection the connection
 * @param pid return location for the process ID
 * @returns #TRUE if uid is filled in with a valid process ID
 */
dbus_bool_t
dbus_connection_get_unix_process_id (DBusConnection *connection,
             unsigned long  *pid)
{
  _dbus_return_val_if_fail (connection != NULL, FALSE);
  _dbus_return_val_if_fail (pid != NULL, FALSE);

  if(bus_context_is_kdbus(bus_connection_get_context (connection)))
    return kdbus_get_connection_unix_process_id(connection, bus_connection_get_name(connection), pid, NULL);

  return dbus_connection_get_unix_process_id_dbus(connection, pid);
}

/*
 * Create connection structure for given name. It is needed to control starters - activatable services
 * and for ListQueued method (as long as kdbus is not supporting it). This connections don't have it's own
 * fd so it is set up on the basis of daemon's transport. Functionality of such connection is limited.
 */
DBusConnection* create_phantom_connection(DBusConnection* connection, const char* name, DBusError* error)
{
    DBusConnection *phantom_connection;
    DBusString Sname;

    _dbus_string_init_const(&Sname, name);

    phantom_connection = _dbus_connection_new_for_used_transport (dbus_connection_get_transport(connection));
    if(phantom_connection == NULL)
        return FALSE;
    if(!bus_connections_setup_connection(bus_connection_get_connections(connection), phantom_connection))
    {
        dbus_connection_unref_phantom(phantom_connection);
        phantom_connection = NULL;
        dbus_set_error (error, DBUS_ERROR_FAILED , "Name \"%s\" could not be acquired", name);
        goto out;
    }
    if(!bus_connection_complete(phantom_connection, &Sname, error))
    {
        bus_connection_disconnected(phantom_connection);
        phantom_connection = NULL;
        goto out;
    }

    _dbus_verbose ("Created phantom connection for %s\n", bus_connection_get_name(phantom_connection));

out:
    return phantom_connection;
}

/*
 * Registers activatable services as kdbus starters.
 */
dbus_bool_t register_kdbus_starters(DBusConnection* connection)
{
    int i,j, len;
    char **services;
    dbus_bool_t retval = FALSE;
    int fd;
    BusTransaction *transaction;
    DBusString name;
    DBusTransport* transport;
    unsigned long int euid;

    transaction = bus_transaction_new (bus_connection_get_context(connection));
    if (transaction == NULL)
    	return FALSE;

    if (!bus_activation_list_services (bus_connection_get_activation (connection), &services, &len))
        return FALSE;

    transport = dbus_connection_get_transport(connection);
    euid = geteuid();

    if(!_dbus_transport_get_socket_fd (transport, &fd))
      return FALSE;

    _dbus_string_init(&name);

    for(i=0; i<len; i++)
    {
        if(!register_kdbus_policy(services[i], transport, euid))
          goto out;

        if (request_kdbus_name(fd, services[i], (DBUS_NAME_FLAG_ALLOW_REPLACEMENT | KDBUS_NAME_STARTER) , 0) < 0)
            goto out;

        if(!_dbus_string_append(&name, services[i]))
        	goto out;
        if(!bus_registry_ensure (bus_connection_get_registry (connection), &name, connection,
        		(DBUS_NAME_FLAG_ALLOW_REPLACEMENT | KDBUS_NAME_STARTER), transaction, NULL))
        	goto out;
        if(!_dbus_string_set_length(&name, 0))
        	goto out;
    }
    retval = TRUE;

out:
    if(retval == FALSE)
    {
        for(j=0; j<i; j++)
            release_kdbus_name(fd, services[j], 0);
    }
    dbus_free_string_array (services);
    _dbus_string_free(&name);
    bus_transaction_cancel_and_free(transaction);
    return retval;
}

/*
 * Updates kdbus starters (activatable services) after configuration was reloaded.
 * It releases all previous starters and registers all new.
 */
dbus_bool_t update_kdbus_starters(DBusConnection* connection)
{
    dbus_bool_t retval = FALSE;
    DBusList **services_old;
    DBusList *link;
    BusService *service = NULL;
    BusTransaction *transaction;
    int fd;

    transaction = bus_transaction_new (bus_connection_get_context(connection));
    if (transaction == NULL)
        return FALSE;

    if(!_dbus_transport_get_socket_fd(dbus_connection_get_transport(connection), &fd))
        goto out;

    services_old = bus_connection_get_services_owned(connection);
    link = _dbus_list_get_first_link(services_old);
    link = _dbus_list_get_next_link (services_old, link); //skip org.freedesktop.DBus which is not starter

    while (link != NULL)
    {
        int ret;

        service = (BusService*) link->data;
        if(service == NULL)
            goto out;

        ret = release_kdbus_name(fd, bus_service_get_name(service), 0);

        if (ret == DBUS_RELEASE_NAME_REPLY_RELEASED)
        {
            if(!bus_service_remove_owner(service, connection, transaction, NULL))
                _dbus_verbose ("Unable to remove\n");
        }
        else if(ret < 0)
            goto out;

        link = _dbus_list_get_next_link (services_old, link);
    }

    if(!register_kdbus_starters(connection))
    {
        _dbus_verbose ("Registering kdbus starters for dbus activatable names failed!\n");
        goto out;
    }
    retval = TRUE;

out:
	bus_transaction_cancel_and_free(transaction);
    return retval;
}

/*
 * Analyzes system broadcasts about id and name changes.
 * Basing on this it sends NameAcquired and NameLost signals and clear phantom connections.
 */
void handleNameOwnerChanged(DBusMessage *msg, BusTransaction *transaction, DBusConnection *connection)
{
    const char *name, *old, *new;

    if(!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old, DBUS_TYPE_STRING, &new, DBUS_TYPE_INVALID))
    {
        _dbus_verbose ("Couldn't get args of NameOwnerChanged signal.\n");//, error.message);
        return;
    }

    _dbus_verbose ("Got NameOwnerChanged signal:\nName: %s\nOld: %s\nNew: %s\n", name, old, new);

    if(!strncmp(name, ":1.", 3))/*if it starts from :1. it is unique name - this might be IdRemoved info*/
    {
        if(!strcmp(name, old))  //yes it is - someone has disconnected
        {
            DBusConnection* conn;

            conn = bus_connections_find_conn_by_name(bus_connection_get_connections(connection), name);
            if(conn)
                bus_connection_disconnected(conn);
        }
    }
    else //it is well-known name
    {
        if((*old != 0) && (strcmp(old, ":1.1")))
        {
            DBusMessage *message;

            if(bus_connections_find_conn_by_name(bus_connection_get_connections(connection), old) == NULL)
                goto next;

            _dbus_verbose ("Owner '%s' lost name '%s'. Sending NameLost.\n", old, name);

            message = dbus_message_new_signal (DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameLost");
            if (message == NULL)
                goto next;

            if (!dbus_message_set_destination (message, old) || !dbus_message_append_args (message,
                                                                 DBUS_TYPE_STRING, &name,
                                                                 DBUS_TYPE_INVALID))
            {
                dbus_message_unref (message);
                goto next;
            }

            bus_transaction_send_from_driver (transaction, connection, message);
            dbus_message_unref (message);
        }
    next:
        if((*new != 0) && (strcmp(new, ":1.1")))
        {
            DBusMessage *message;

            _dbus_verbose ("Owner '%s' acquired name '%s'. Sending NameAcquired.\n", new, name);

            message = dbus_message_new_signal (DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameAcquired");
            if (message == NULL)
                return;

            if (!dbus_message_set_destination (message, new) || !dbus_message_append_args (message,
                                                                 DBUS_TYPE_STRING, &name,
                                                                 DBUS_TYPE_INVALID))
            {
                dbus_message_unref (message);
                return;
            }

            bus_transaction_send_from_driver (transaction, connection, message);
            dbus_message_unref (message);
        }
    }

    if(bus_transaction_send(transaction, connection, msg))
      _dbus_verbose ("NameOwnerChanged sent\n");
    else
      _dbus_verbose ("Sending NameOwnerChanged failed\n");
}
