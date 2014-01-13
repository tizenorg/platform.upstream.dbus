/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-common.c  kdbus related utils for daemon and libdbus
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
#include "kdbus.h"
#include "kdbus-common.h"
#include "dbus-transport-kdbus.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus-internals.h>
#include <dbus/dbus-shared.h>

static struct kdbus_item *make_policy_name(const char *name)
{
  struct kdbus_item *p;
  __u64 size;

  size = offsetof(struct kdbus_item, policy.name) + strlen(name) + 1;
  p = malloc(size);
  if (!p)
	  return NULL;
  memset(p, 0, size);
  p->size = size;
  p->type = KDBUS_ITEM_POLICY_NAME;
  memcpy(p->policy.name, name, strlen(name) + 1);

  return p;
}

static  struct kdbus_item *make_policy_access(__u64 type, __u64 bits, __u64 id)
{
  struct kdbus_item *p;
  __u64 size = sizeof(*p);

  p = malloc(size);
  if (!p)
	  return NULL;

  memset(p, 0, size);
  p->size = size;
  p->type = KDBUS_ITEM_POLICY_ACCESS;
  p->policy.access.type = type;
  p->policy.access.bits = bits;
  p->policy.access.id = id;

  return p;
}

static void append_policy(struct kdbus_cmd_policy *cmd_policy, struct kdbus_item *policy, __u64 max_size)
{
  struct kdbus_item *dst = (struct kdbus_item *) ((char *) cmd_policy + cmd_policy->size);

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
 * @param transport - transport
 * @param owner_uid - uid or euid of the process being owner of the name
 *
 * @returns #TRUE on success
 */
dbus_bool_t register_kdbus_policy(const char* name, DBusTransport *transport, unsigned long int owner_uid)
{
  struct kdbus_cmd_policy *cmd_policy;
  struct kdbus_item *policy;
  int size = 0xffff;
  int fd;

  if(!_dbus_transport_get_socket_fd (transport, &fd))
    return FALSE;

  cmd_policy = alloca(size);
  memset(cmd_policy, 0, size);

  policy = (struct kdbus_item *) cmd_policy->policies;
  cmd_policy->size = offsetof(struct kdbus_cmd_policy, policies);

  policy = make_policy_name(name);
  append_policy(cmd_policy, policy, size);

  policy = make_policy_access(KDBUS_POLICY_ACCESS_USER, KDBUS_POLICY_OWN, owner_uid);
  append_policy(cmd_policy, policy, size);

  policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_RECV, 0);
  append_policy(cmd_policy, policy, size);

  policy = make_policy_access(KDBUS_POLICY_ACCESS_WORLD, KDBUS_POLICY_SEND, 0);
  append_policy(cmd_policy, policy, size);

  if (ioctl(fd, KDBUS_CMD_EP_POLICY_SET, cmd_policy) < 0)
    {
      _dbus_verbose ("Error setting policy: %m, %d\n", errno);
      return FALSE;
    }

  _dbus_verbose("Policy %s set correctly\n", name);
  return TRUE;
}

/**
 *
 * Asks the bus to assign the given name to the connection.
 *
 * Use same flags as original dbus version with one exception below.
 * Result flag #DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER is currently
 * never returned by kdbus, instead DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
 * is returned by kdbus.
 *
 * @param fd - file descriptor of the connection
 * @param name the name to request
 * @param flags flags
 * @param id unique id of the connection for which the name is being registered
 * @returns a DBus result code on success, -errno on error
 */
int request_kdbus_name(int fd, const char *name, const __u64 flags, __u64 id)
{
  struct kdbus_cmd_name *cmd_name;

  __u64 size = sizeof(*cmd_name) + strlen(name) + 1;
  __u64 flags_kdbus = 0;

  cmd_name = alloca(size);

  strcpy(cmd_name->name, name);
  cmd_name->size = size;

  if(flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)
    flags_kdbus |= KDBUS_NAME_ALLOW_REPLACEMENT;
  if(!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE))
    flags_kdbus |= KDBUS_NAME_QUEUE;
  if(flags & DBUS_NAME_FLAG_REPLACE_EXISTING)
    flags_kdbus |= KDBUS_NAME_REPLACE_EXISTING;
  if(flags & KDBUS_NAME_STARTER_NAME)
    flags_kdbus |= KDBUS_NAME_STARTER_NAME;

  cmd_name->flags = flags_kdbus;
  cmd_name->id = id;

  _dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name))
    {
      _dbus_verbose ("error acquiring name '%s': %m, %d\n", name, errno);
      if(errno == EEXIST)
        return DBUS_REQUEST_NAME_REPLY_EXISTS;
      if(errno == EALREADY)
        return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
      return -errno;
    }

  _dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if(cmd_name->flags & KDBUS_NAME_IN_QUEUE)
    return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
  else
    return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
}

/**
 *
 * Releases well-known name - the connections resign from the name
 * which can be then assigned to another connection or the connection
 * is being removed from the queue for that name
 *
 * @param fd - file descriptor of the connection
 * @param name the name to request
 * @param id unique id of the connection for which the name is being released
 * @returns a DBus result code on success, -errno on error
 */
int release_kdbus_name(int fd, const char *name, __u64 id)
{
  struct kdbus_cmd_name *cmd_name;

  __u64 size = sizeof(*cmd_name) + strlen(name) + 1;

  cmd_name = alloca(size);
  cmd_name->id = id;
  strcpy(cmd_name->name, name);
  cmd_name->size = size;

  if (ioctl(fd, KDBUS_CMD_NAME_RELEASE, cmd_name))
    {
      if((errno == ESRCH) || (errno == ENXIO))
        return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
      else if (errno == EPERM)
        return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
      _dbus_verbose ("error releasing name '%s' for id:%llu. Error: %m, %d\n", name, (unsigned long long)id, errno);
      return -errno;
    }

  _dbus_verbose("Name '%s' released\n", name);

  return DBUS_RELEASE_NAME_REPLY_RELEASED;
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

  memset(pInfo, 0, sizeof(struct nameInfo));

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

  memset(cmd, 0, sizeof(struct kdbus_cmd_conn_info));
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
          pInfo->processId = item->creds.pid;
        }

      if(item->type == KDBUS_ITEM_SECLABEL)
        {
          pInfo->sec_label_len = item->size - KDBUS_ITEM_HEADER_SIZE - 1;
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
 *  Asks kdbus for uid of the owner of the name given in the message
 */
dbus_bool_t kdbus_connection_get_unix_user(DBusConnection* connection, const char* name, unsigned long* uid, DBusError* error)
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
dbus_bool_t kdbus_connection_get_unix_process_id(DBusConnection* connection, const char* name, unsigned long* pid, DBusError* error)
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
