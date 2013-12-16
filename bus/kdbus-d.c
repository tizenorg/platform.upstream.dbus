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
#define KDBUS_FOR_SBB
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
      size += KDBUS_PART_SIZE(name_size + 1);  //well known name
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
  struct kdbus_cmd_conn_info *cmd;
  int ret;
  int fd;
  uint64_t size;
  __u64 id = 0;

  pInfo->sec_label_len = 0;
  pInfo->sec_label = NULL;

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    return -EPERM;

  size = sizeof(struct kdbus_cmd_conn_info);
  if((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))  /* if name starts with ":1." it is a unique name and should be send as number */
     id = strtoull(&name[3], NULL, 10);
  if(id == 0)
    size += strlen(name) + 1;

  cmd = alloca(size);
  if (!cmd)
  {
    _dbus_verbose("Error allocating memory for: %s,%s\n", _dbus_strerror (errno), _dbus_error_from_errno (errno));
    return -errno;
  }

  cmd->size = size;
  cmd->id = id;
  if(id == 0)
    memcpy(cmd->name, name, strlen(name) + 1);

  again:
  ret = ioctl(fd, KDBUS_CMD_CONN_INFO, cmd);
  if (ret < 0)
  {
    if(errno == EINTR)
      goto again;
    pInfo->uniqueId = 0;
    return -errno;
  }
  else
  {
    struct kdbus_conn_info *info;
    struct kdbus_item *item;

    info = (struct kdbus_conn_info *)((char*)dbus_transport_get_pool_pointer(transport) + cmd->offset);
    pInfo->uniqueId = info->id;

    item = info->items;
    while((uint8_t *)(item) < (uint8_t *)(info) + info->size)
    {
      if(item->type == KDBUS_ITEM_CREDS)
        {
          pInfo->userId = item->creds.uid;
          pInfo->processId = item->creds.uid;
        }

      if(item->type == KDBUS_ITEM_SECLABEL)
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
        }

      item = KDBUS_PART_NEXT(item);
    }

    again2:
    if (ioctl(fd, KDBUS_CMD_FREE, &cmd->offset) < 0)
    {
      if(errno == EINTR)
        goto again2;
      _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);
      return -errno;
    }
  }

  return ret;
}

/*
 * Creates kdbus bus of given type.
 */
char* make_kdbus_bus(DBusBusType type, const char* address, DBusError *error)
{
  // TODO Function alloca() used. In upstream there was a patch proposing to
  // replace alloca() with malloc() to assure memory alignment. If there will be
  // suggestion to use malloc instead of alloca this function has to be modified
  struct kdbus_cmd_bus_make *bus_make;
  struct kdbus_item *item;
  __u64 name_size, item_size, bus_make_size;
  int fdc, ret;
  char *addr_value = NULL;
  char *bus = NULL;
  char *name = NULL;

  if(type == DBUS_BUS_SYSTEM)
    name_size = snprintf(name, 0, "%u-kdbus-%s", getuid(), "system") + 1;
  else if(type == DBUS_BUS_SESSION)
    name_size = snprintf(name, 0, "%u-kdbus", getuid()) + 1;
  else
    name_size = snprintf(name, 0, "%u-kdbus-%u", getuid(), getpid()) + 1;

  name = alloca(name_size);
  if (!name)
    {
      return NULL;
    }

  item_size = KDBUS_PART_HEADER_SIZE + name_size;
  bus_make_size = sizeof(struct kdbus_cmd_bus_make) + item_size;

  bus_make = alloca(bus_make_size);
  if (!bus_make)
    {
      return NULL;
    }

  item = bus_make->items;
  item->size = item_size;
  item->type = KDBUS_ITEM_MAKE_NAME;

  if(type == DBUS_BUS_SYSTEM)
    sprintf(name, "%u-kdbus-%s", getuid(), "system");
  else if(type == DBUS_BUS_SESSION)
    sprintf(name, "%u-kdbus", getuid());
  else
    sprintf(name, "%u-kdbus-%u", getuid(), getpid());

  memcpy((bus_make->items)->str, name, name_size);

  bus_make->bloom_size = 64;
  bus_make->size = bus_make_size;

#ifdef POLICY_TO_KDBUS
  bus_make->flags = KDBUS_MAKE_ACCESS_WORLD;
#else
  bus_make->flags = KDBUS_MAKE_POLICY_OPEN;
#endif

  addr_value = strchr(address, ':') + 1;
  if(*addr_value)
    {
      if(!strcmp(addr_value, "sbb"))
        bus_make->flags |= KDBUS_MAKE_SBB_OFFSET;
      else
        {
          dbus_set_error_const(error, DBUS_ERROR_BAD_ADDRESS, "Invalid address parameter.");
          return NULL;
        }
    }

  _dbus_verbose("Opening /dev/kdbus/control\n");
  fdc = open("/dev/kdbus/control", O_RDWR|O_CLOEXEC);
  if (fdc < 0)
    {
      _dbus_verbose("--- error %d (%m)\n", fdc);
      dbus_set_error(error, DBUS_ERROR_FAILED, "Opening /dev/kdbus/control failed: %d (%m)", fdc);
      return NULL;
    }

  _dbus_verbose("Creating bus '%s'\n", (bus_make->items[0]).str);
  ret = ioctl(fdc, KDBUS_CMD_BUS_MAKE, bus_make);
  if (ret)
    {
      _dbus_verbose("--- error %d (%m)\n", errno);
      dbus_set_error(error, DBUS_ERROR_FAILED, "Creating bus '%s' failed: %d (%m)",
          (bus_make->items[0]).str, errno);
      return NULL;
    }

  if (asprintf(&bus, "kdbus:path=/dev/kdbus/%s/bus", (bus_make->items[0]).str) < 0)
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

static dbus_bool_t add_matches_for_kdbus_broadcasts(DBusConnection* connection)
{
  struct kdbus_cmd_match* pCmd_match;
  struct kdbus_item *pItem;
  uint64_t size;
  int fd;
  DBusTransport *transport;
  const char* unique_name;

  transport = dbus_connection_get_transport(connection);

  if(!_dbus_transport_get_socket_fd(transport, &fd))
    {
      errno = EPERM;
      return FALSE;
    }

  size = sizeof(struct kdbus_cmd_match);
  size += KDBUS_PART_SIZE(1)*3 + KDBUS_PART_SIZE(sizeof(__u64))*2;  /*3 name related items plus 2 id related items*/

  pCmd_match = alloca(size);
  if(pCmd_match == NULL)
    {
      errno = ENOMEM;
      return FALSE;
    }

  unique_name = dbus_bus_get_unique_name(connection);

  pCmd_match->id = strtoull(&unique_name[3], NULL, 10);
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

  if(!add_matches_for_kdbus_broadcasts(connection))
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
#ifdef POLICY_TO_KDBUS
    if(!register_kdbus_policy(DBUS_SERVICE_DBUS, dbus_connection_get_transport(connection), geteuid()))
      return FALSE;
#endif

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
	struct kdbus_cmd_name_list __attribute__ ((__aligned__(8))) cmd;
	struct kdbus_name_list *name_list;
	struct kdbus_cmd_name *name;
	DBusTransport *transport = dbus_connection_get_transport(connection);
	dbus_bool_t ret_val = FALSE;
	char** list;
	int list_len = 0;
	int i = 0;
	int j;

	if(!_dbus_transport_get_socket_fd(transport, &fd))
	  return FALSE;

  cmd.flags = KDBUS_NAME_LIST_NAMES | KDBUS_NAME_LIST_UNIQUE;

again:
	if(ioctl(fd, KDBUS_CMD_NAME_LIST, &cmd))
	{
		if(errno == EINTR)
			goto again;
		else
		{
			_dbus_verbose("kdbus error asking for name list: err %d (%m)\n",errno);
			return FALSE;
		}
	}

	name_list = (struct kdbus_name_list *)((char*)dbus_transport_get_pool_pointer(transport) + cmd.offset);

  for (name = name_list->names; (uint8_t *)(name) < (uint8_t *)(name_list) + name_list->size; name = KDBUS_PART_NEXT(name))
    list_len++;

  _dbus_verbose ("List len: %d\n", list_len);

  list = malloc(sizeof(char*) * (list_len + 1));
  if(list == NULL)
    goto out;

  for (name = name_list->names; (uint8_t *)(name) < (uint8_t *)(name_list) + name_list->size; name = KDBUS_PART_NEXT(name))
  {
      if(*name->name)
      {
        list[i] = strdup(name->name);
        if(list[i] == NULL)
          goto out;
      }
      else
      {
        list[i] = malloc(snprintf(list[i], 0, ":1.%llu0", (unsigned long long)name->id));
        if(list[i] == NULL)
          goto out;
        sprintf(list[i], ":1.%llu", (unsigned long long int)name->id);
      }
    _dbus_verbose ("Name %d: %s\n", i, list[i]);
    ++i;
  }

  list[i] = NULL;
	*array_len = list_len;
	*listp = list;
	ret_val = TRUE;

out:
  if (ioctl(fd, KDBUS_CMD_FREE, &cmd.offset) < 0)
  {
    if(errno == EINTR)
      goto out;
    _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);
    ret_val = FALSE;
  }
  if(ret_val == FALSE)
    {
      for(j=0; j<i; j++)
        free(list[j]);
      free(list);
      *array_len = 0;
      *listp = NULL;
    }

	return ret_val;
}

/*
 * Asks kdbus for list of connections being in the queue to own
 * given well-known name. The list includes the owner of the name on the
 * first position.
 */
dbus_bool_t kdbus_list_queued (DBusConnection *connection, DBusList  **return_list,
                               const char *name, DBusError  *error)
{
  int fd;
  dbus_bool_t ret_val = FALSE;
  int name_length;
  struct kdbus_cmd_conn_info *pCmd;
  __u64 cmd_size;
  DBusTransport *transport = dbus_connection_get_transport(connection);
  struct kdbus_name_list *name_list;
  struct kdbus_cmd_name *owner;

  _dbus_assert (*return_list == NULL);

  name_length = strlen(name) + 1;
  cmd_size = sizeof(struct kdbus_cmd_conn_info) + name_length;
  pCmd = alloca(cmd_size);
  if(pCmd == NULL)
    goto out;
  pCmd->size = cmd_size;
  pCmd->id = 0;
  memcpy(pCmd->name, name, name_length);

  _dbus_verbose ("Asking for queued owners of %s\n", pCmd->name);

  _dbus_transport_get_socket_fd(transport, &fd);

  again:
  if(ioctl(fd, KDBUS_CMD_NAME_LIST_QUEUED, pCmd))
    {
      if(errno == EINTR)
        goto again;
      else if(errno == ESRCH)
        {
          dbus_set_error (error, DBUS_ERROR_NAME_HAS_NO_OWNER,
                      "Could not get owners of name '%s': no such name", name);
          return FALSE;
        }
      else
        {
          _dbus_verbose("kdbus error asking for queued owners list: err %d (%m)\n",errno);
          goto out;
        }
    }

  name_list = (struct kdbus_name_list *)((char*)dbus_transport_get_pool_pointer(transport) + pCmd->offset);

  for (owner = name_list->names; (uint8_t *)(owner) < (uint8_t *)(name_list) + name_list->size; owner = KDBUS_PART_NEXT(owner))
    {
      char *uname = NULL;

      _dbus_verbose ("Got queued owner id: %llu\n", (unsigned long long)owner->id);
      uname = malloc(snprintf(uname, 0, ":1.%llu0", (unsigned long long)owner->id));
      if(uname == NULL)
        goto out;
      sprintf(uname, ":1.%llu", (unsigned long long int)owner->id);
      if (!_dbus_list_append (return_list, uname))
        goto out;
    }

  ret_val = TRUE;

  out:
  if (ioctl(fd, KDBUS_CMD_FREE, &pCmd->offset) < 0)
  {
    if(errno == EINTR)
      goto out;
    _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);
    ret_val = FALSE;
  }
  if(ret_val == FALSE)
    {
      DBusList *link;

      dbus_set_error (error, _dbus_error_from_errno (errno),
          "Failed to list queued owners of \"%s\": %s",
          name, _dbus_strerror (errno));

      link = _dbus_list_get_first_link (return_list);
      while (link != NULL)
        {
          DBusList *next = _dbus_list_get_next_link (return_list, link);

          if(link->data != NULL)
            free(link->data);

          _dbus_list_free_link (link);
          link = next;
        }
    }

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
  else if((ret != -ENOENT) && (ret != -ENXIO))
    _dbus_verbose("kdbus error sending name query: err %d (%m)\n", ret);

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
  else if((inter_ret == -ENOENT) || (inter_ret == -ENXIO)) //name has no owner
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
	else if((inter_ret == -ENOENT) || (inter_ret == -ENXIO)) //name has no owner
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
	if((inter_ret == -ENOENT) || (inter_ret == -ENXIO)) //name has no owner
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

    transaction = bus_transaction_new (bus_connection_get_context(connection));
    if (transaction == NULL)
    	return FALSE;

    if (!bus_activation_list_services (bus_connection_get_activation (connection), &services, &len))
        return FALSE;

    transport = dbus_connection_get_transport(connection);

    if(!_dbus_transport_get_socket_fd (transport, &fd))
      return FALSE;

    _dbus_string_init(&name);

    for(i=0; i<len; i++)
    {
#ifdef POLICY_TO_KDBUS
        if(!register_kdbus_policy(services[i], transport, geteuid()))
          goto out;
#endif

        if (request_kdbus_name(fd, services[i], (DBUS_NAME_FLAG_ALLOW_REPLACEMENT | KDBUS_NAME_STARTER_NAME) , 0) < 0)
            goto out;

        if(!_dbus_string_append(&name, services[i]))
        	goto out;
        if(!bus_registry_ensure (bus_connection_get_registry (connection), &name, connection,
        		(DBUS_NAME_FLAG_ALLOW_REPLACEMENT | KDBUS_NAME_STARTER_NAME), transaction, NULL))
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
        if((*old != 0) && (strcmp(old, bus_connection_get_name(connection))))
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
        if((*new != 0) && (strcmp(new, bus_connection_get_name(connection))))
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
