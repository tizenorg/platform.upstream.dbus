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
 * @param transport - transport
 * @param owner_uid - uid or euid of the process being owner of the name
 *
 * @returns #TRUE on success
 */
dbus_bool_t register_kdbus_policy(const char* name, DBusTransport *transport, unsigned long int owner_uid)
{
  struct kdbus_cmd_policy *cmd_policy;
  struct kdbus_policy *policy;
  int size = 0xffff;
  int fd;

  if(!_dbus_transport_get_socket_fd (transport, &fd))
    return FALSE;

  cmd_policy = alloca(size);
  memset(cmd_policy, 0, size);

  policy = (struct kdbus_policy *) cmd_policy->policies;
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
  if(flags & KDBUS_NAME_STARTER)
    flags_kdbus |= KDBUS_NAME_STARTER;

  cmd_name->flags = flags_kdbus;
  cmd_name->id = id;
  //	cmd_name->conn_flags = 0;

  _dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name))
    {
      _dbus_verbose ("error acquiring name '%s': %m, %d\n", name, errno);
      if(errno == EEXIST)
        return DBUS_REQUEST_NAME_REPLY_EXISTS;
      return -errno;
    }

  _dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if(cmd_name->flags & KDBUS_NAME_IN_QUEUE)
    return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;
  else
    return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
  /*todo now 1 code is never returned -  DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER
   * because kdbus never returns it now
   */
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
      if(errno == ESRCH)
        return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
      else if (errno == EPERM)
        return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
      _dbus_verbose ("error releasing name '%s' for id:%llu. Error: %m, %d\n", name, (unsigned long long)id, errno);
      return -errno;
    }

  _dbus_verbose("Name '%s' released\n", name);

  return DBUS_RELEASE_NAME_REPLY_RELEASED;
}
