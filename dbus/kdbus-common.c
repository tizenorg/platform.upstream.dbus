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
#include <config.h>
#include "kdbus.h"
#include "kdbus-common.h"
#include "dbus-transport-kdbus.h"
#include "dbus-valgrind-internal.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus-internals.h>
#include <dbus/dbus-shared.h>
#include "dbus-signals.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

struct kdbus_t
{
  int fd;                                                     /**< File descriptor */
  void *mmap_ptr;                   /**< Mapped memory where kdbus (kernel) writes
                                     *   messages incoming to us.
                                     */
  size_t pool_size;                                     /**< Size of mapped memory */
  __u64 id;                                       /**< unique id of the connection */
  char bus_id[sizeof (((struct kdbus_cmd_hello *)(0))->id128)];  /**< id of the bus */
  struct kdbus_bloom_parameter bloom;                         /**< bloom parameters*/
};

/* ALIGN8 and KDBUS_FOREACH taken from systemd */
#define ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_FOREACH(iter, first, _size)                               \
        for (iter = (first);                                            \
             ((uint8_t *)(iter) < (uint8_t *)(first) + (_size)) &&      \
               ((uint8_t *)(iter) >= (uint8_t *)(first));               \
             iter = (void*)(((uint8_t *)iter) + ALIGN8((iter)->size)))

static int
safe_ioctl (int fd,
            unsigned long request,
            void *data)
{
  int ret;

  do {
    ret = ioctl (fd, request, data);
  }
  while (-1 == ret && EINTR == errno);

  return ret;
}

static int
free_by_offset (kdbus_t  *kdbus,
                __u64     offset)
{
  struct kdbus_cmd_free cmd;

  /*
   * Kdbus requires to initialize ioctl params partially. Some parts
   * are for data passed from user to kernel, and other parts
   * for data passed from kernel to user.
   *
   * Valgrind detects when uninitialized data is passed to kernel
   * and has no way to know that it is meant to be filled by kernel.
   * Thus, we initialize params for Valgrind to stop complaining.
   */
  VALGRIND_MAKE_MEM_DEFINED (&cmd, sizeof (cmd));

  cmd.size = sizeof (cmd);
  cmd.offset = offset;
  cmd.flags = 0;

  if (safe_ioctl (kdbus->fd, KDBUS_CMD_FREE, &cmd )!= 0)
    return errno;

  return 0;
}

static void make_item_name (const char *name, struct kdbus_item *item)
{
  size_t len = strlen (name) + 1;
  item->size = KDBUS_ITEM_HEADER_SIZE + len;
  item->type = KDBUS_ITEM_NAME;

  memcpy (item->str, name, len);
}

/**
 * Adds an item in the current position of items array.
 *
 * @param item item to fill
 * @param item_type type of the item
 * @param string value of the item
 * @param string_size size of the value
 * @returns pointer to the next item
 */
struct kdbus_item *
_kdbus_item_add_string (struct kdbus_item *item,
                        __u64              item_type,
                        const char        *item_string,
                        __u64              item_string_size)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + item_string_size;
  item->type = item_type;
  memcpy (item->str, item_string, item_string_size);
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_payload_memfd (struct kdbus_item *item,
                               __u64              start,
                               __u64              size,
                               int                fd)
{
  item->type = KDBUS_ITEM_PAYLOAD_MEMFD;
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_memfd);
  item->memfd.start = start;
  item->memfd.size = size;
  item->memfd.fd = fd;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_payload_vec (struct kdbus_item *item,
                             __u64              size,
                             __u64              address_or_offset)
{
  item->type = KDBUS_ITEM_PAYLOAD_VEC;
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_vec);
  item->vec.size = size;
  item->vec.address = address_or_offset;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_fds (struct kdbus_item *item,
                     const int         *fds,
                     int                fds_count)
{
  item->type = KDBUS_ITEM_FDS;
  item->size = KDBUS_ITEM_HEADER_SIZE + (__u64)fds_count * sizeof (int);
  memcpy (item->fds, fds, fds_count * sizeof (int));
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_bloom_filter (struct kdbus_item          *item,
                              kdbus_t                    *kdbus,
                              struct kdbus_bloom_filter **out_ptr)
{
  item->type = KDBUS_ITEM_BLOOM_FILTER;
  item->size = KDBUS_ITEM_HEADER_SIZE
               + sizeof (struct kdbus_bloom_filter)
               + kdbus->bloom.size;
  memset (item->bloom_filter.data, 0, kdbus->bloom.size);
  item->bloom_filter.generation = 0;
  *out_ptr = &item->bloom_filter;
  return KDBUS_ITEM_NEXT (item);
}

kdbus_bloom_data_t *
_kdbus_bloom_filter_get_data (struct kdbus_bloom_filter *bloom_filter)
{
  return bloom_filter->data;
}

struct kdbus_item *
_kdbus_item_add_name_change (struct kdbus_item *item,
                             __u64              old_id,
                             __u64              old_id_flags,
                             __u64              new_id,
                             __u64              new_id_flags)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_notify_name_change);
  item->type = KDBUS_ITEM_NAME_CHANGE;
  item->name_change.old_id.id = old_id;
  item->name_change.old_id.flags = old_id_flags;
  item->name_change.new_id.id = new_id;
  item->name_change.new_id.flags = new_id_flags;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_id_add (struct kdbus_item *item,
                        __u64              id,
                        __u64              id_flags)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_notify_id_change);
  item->type = KDBUS_ITEM_ID_ADD;
  item->id_change.id = id;
  item->id_change.flags = id_flags;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_id (struct kdbus_item *item,
                    __u64              id)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_notify_id_change);
  item->type = KDBUS_ITEM_ID;
  item->id = id;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_bloom_mask (struct kdbus_item   *item,
                            kdbus_t             *kdbus,
                            kdbus_bloom_data_t **bloom)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + kdbus->bloom.size;
  item->type = KDBUS_ITEM_BLOOM_MASK;
  memset (item->data64, 0, kdbus->bloom.size);
  if (NULL != bloom)
    *bloom = item->data64;
  return KDBUS_ITEM_NEXT (item);
}

static inline void *
get_from_offset (kdbus_t *kdbus,
                 __u64    offset)
{
  return ((char *)kdbus->mmap_ptr) + offset;
}

kdbus_t *
_kdbus_new ()
{
  return dbus_new (kdbus_t, 1);
}

void
_kdbus_free (kdbus_t *kdbus)
{
  dbus_free (kdbus);
}

/**
 * Opens a connection to the kdbus bus
 *
 * @param kdbus kdbus object
 * @param path the path to kdbus bus
 * @returns 0 on success, -errno on failure
 */
int
_kdbus_open (kdbus_t *kdbus, const char *path)
{
  int fd = open (path, O_RDWR|O_CLOEXEC|O_NONBLOCK);
  if (-1 == fd)
    return -errno;

  kdbus->fd = fd;
  return 0;
}

int
_kdbus_close (kdbus_t *kdbus)
{
  int ret;
  int errclose = 0;
  int errunmap = 0;

  do
  {
    ret = close (kdbus->fd);
  } while (-1 == ret && EINTR == errno);
  if (-1 == ret)
    errclose = errno;

  ret = munmap (kdbus->mmap_ptr, kdbus->pool_size);
  if (-1 == ret)
    errunmap = errno;

  if (0 != errclose)
    return -errclose;
  if (0 != errunmap)
    return -errunmap;
  return 0;
}

int
_kdbus_get_fd (kdbus_t *kdbus)
{
  return kdbus->fd;
}

__u64
_kdbus_get_id (kdbus_t *kdbus)
{
  return kdbus->id;
}

char *
_kdbus_get_bus_id (kdbus_t *kdbus)
{
  return kdbus->bus_id;
}

__u64
_kdbus_get_bus_id_size (void)
{
  return sizeof (((struct kdbus_t *)(0))->bus_id);
}

int
_kdbus_hello (kdbus_t       *kdbus,
              __u64          flags,
              __u64          attach_flags_send,
              __u64          attach_flags_recv,
              __u64          pool_size,
              const char    *activator_name,
              const char    *connection_name)
{
  struct kdbus_cmd_hello  *hello;
  struct kdbus_item *item, *items;
  __u64 hello_size;
  size_t activator_name_size = 0;
  size_t connection_name_size = 0;
  __u64 offset;
  __u64 items_size;

  hello_size = sizeof (struct kdbus_cmd_hello);

  if (NULL != activator_name)
    {
      activator_name_size = strlen (activator_name) + 1;
      hello_size += KDBUS_ITEM_SIZE (activator_name_size);
    }

  if (NULL != connection_name)
    {
      connection_name_size  = strlen (connection_name) + 1;
      hello_size += KDBUS_ITEM_SIZE (connection_name_size);
    }

  hello = dbus_malloc (hello_size);
  if (NULL == hello)
    return -ENOMEM;

  VALGRIND_MAKE_MEM_DEFINED (hello, hello_size);

  hello->flags = flags;
  hello->attach_flags_send = attach_flags_send;
  hello->attach_flags_recv = attach_flags_recv;
  hello->pool_size = pool_size;

  item = hello->items;
  if (connection_name_size > 0)
    item = _kdbus_item_add_string (item,
                                   KDBUS_ITEM_CONN_DESCRIPTION,
                                   connection_name,
                                   connection_name_size);
  if (activator_name_size > 0)
    {
      _kdbus_item_add_string (item,
                              KDBUS_ITEM_NAME,
                              activator_name,
                              activator_name_size);
      hello->flags |= KDBUS_HELLO_ACTIVATOR;
    }

  hello->size = hello_size;

  if (safe_ioctl (kdbus->fd, KDBUS_CMD_HELLO, hello) != 0)
    {
      dbus_free (hello);
      return -errno;
    }

  kdbus->id = hello->id;
  memcpy (kdbus->bus_id, hello->id128, sizeof (kdbus->bus_id));

  offset = hello->offset;
  items_size = hello->items_size;
  dbus_free (hello);

  kdbus->mmap_ptr = mmap (NULL, pool_size, PROT_READ, MAP_SHARED, kdbus->fd, 0);
  if (MAP_FAILED == kdbus->mmap_ptr)
      return -errno;

  kdbus->pool_size = pool_size;

  items = get_from_offset (kdbus, offset);
  KDBUS_FOREACH (item, items, items_size)
    {
      if (KDBUS_ITEM_BLOOM_PARAMETER == item->type)
        kdbus->bloom = item->bloom_parameter;
    }

  return 0;
}

int
_kdbus_send (kdbus_t           *kdbus,
             __u64              flags,
             struct kdbus_msg  *msg,
             struct kdbus_msg **msg_reply)
{
  struct kdbus_cmd_send cmd;

  VALGRIND_MAKE_MEM_DEFINED (&cmd, sizeof (cmd));

  cmd.size = sizeof (cmd);
  cmd.msg_address = (uintptr_t)msg;
  cmd.flags = flags;

  if (-1 == safe_ioctl (kdbus->fd, KDBUS_CMD_SEND, &cmd))
    return errno;

  if (flags & KDBUS_SEND_SYNC_REPLY)
    {
      if (NULL != msg_reply)
        *msg_reply = get_from_offset (kdbus, cmd.reply.offset);
      else
        free_by_offset (kdbus, cmd.reply.offset);
    }

  return 0;
}

int
_kdbus_recv (kdbus_t           *kdbus,
             __u64              flags,
             __s64              priority,
             struct kdbus_msg **msg)
{
  struct kdbus_cmd_recv cmd;

  VALGRIND_MAKE_MEM_DEFINED (&cmd, sizeof (cmd));

  cmd.size = sizeof (cmd);
  cmd.flags = flags;
  cmd.priority = priority;

  if (-1 == safe_ioctl (kdbus->fd, KDBUS_CMD_RECV, &cmd))
    return errno;

  *msg = get_from_offset (kdbus, cmd.msg.offset);

  return 0;
}

int
_kdbus_list (kdbus_t            *kdbus,
             __u64               flags,
             struct kdbus_info **name_list,
             __u64              *list_size)
{
  struct kdbus_cmd_list cmd;

  VALGRIND_MAKE_MEM_DEFINED (&cmd, sizeof (cmd));

  cmd.size = sizeof (cmd);
  cmd.flags = flags;

  if (-1 == safe_ioctl (kdbus->fd, KDBUS_CMD_LIST, &cmd))
    return errno;

  *name_list = get_from_offset (kdbus, cmd.offset);
  *list_size = cmd.list_size;

  return 0;
}

__u64
_kdbus_compute_match_items_size (kdbus_t       *kdbus,
                                 dbus_bool_t    with_bloom_mask,
                                 __u64          sender_id,
                                 const char    *sender_name)
{
  __u64 size = 0;

  if (with_bloom_mask)
    size += KDBUS_ITEM_SIZE (kdbus->bloom.size);

  if (KDBUS_MATCH_ID_ANY != sender_id) /* unique name present */
    size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_notify_id_change));
  else if (NULL != sender_name)
    size += KDBUS_ITEM_SIZE (strlen (sender_name) + 1);

  return size;
}

struct kdbus_cmd_match *
_kdbus_new_cmd_match (kdbus_t       *kdbus,
                      __u64          items_size,
                      __u64          flags,
                      __u64          cookie)
{
  struct kdbus_cmd_match *cmd;
  __u64 cmd_size = sizeof (*cmd) + items_size;
  cmd = dbus_malloc (cmd_size);
  if (NULL == cmd)
    return NULL;

  VALGRIND_MAKE_MEM_DEFINED (cmd, cmd_size);

  cmd->size = cmd_size;
  cmd->flags = flags;
  cmd->cookie = cookie;

  return cmd;
}

void
_kdbus_free_cmd_match (struct kdbus_cmd_match *cmd)
{
  dbus_free (cmd);
}

int
_kdbus_add_match_name_change (kdbus_t *kdbus,
                              __u64    flags,
                              __u64    cookie,
                              __u64    old_id,
                              __u64    old_id_flags,
                              __u64    new_id,
                              __u64    new_id_flags)
{
  struct kdbus_cmd_match *cmd;
  struct kdbus_item *item;
  int ret;

  cmd = _kdbus_new_cmd_match (kdbus,
                              KDBUS_ITEM_SIZE (sizeof (struct kdbus_notify_name_change)),
                              flags,
                              cookie);
  if (NULL == cmd)
    return ENOMEM;

  item = cmd->items;
  _kdbus_item_add_name_change (item,
                               old_id, old_id_flags,
                               new_id, new_id_flags);

  ret = safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (0 == ret)
    {
      item->type = KDBUS_ITEM_NAME_ADD;
      ret = safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_ADD, cmd);
      if (0 == ret)
        {
          item->type = KDBUS_ITEM_NAME_REMOVE;
          ret = safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_ADD, cmd);
        }
    }

  if (0 != ret)
    ret = errno;

  _kdbus_free_cmd_match (cmd);
  return ret;
}

int
_kdbus_add_match_id_change (kdbus_t *kdbus,
                            __u64    flags,
                            __u64    cookie,
                            __u64    id,
                            __u64    id_flags)
{
  struct kdbus_cmd_match *cmd;
  struct kdbus_item *item;
  int ret;

  cmd = _kdbus_new_cmd_match (kdbus,
                              KDBUS_ITEM_SIZE (sizeof (struct kdbus_notify_id_change)),
                              flags,
                              cookie);
  if (NULL == cmd)
    return ENOMEM;

  item = cmd->items;
  _kdbus_item_add_id_add (item, id, id_flags);

  ret = safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (0 == ret)
    {
      item->type = KDBUS_ITEM_ID_REMOVE;
      ret = safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_ADD, cmd);
    }

  if (0 != ret)
    ret = errno;

  _kdbus_free_cmd_match (cmd);
  return ret;
}

int _kdbus_add_match (kdbus_t *kdbus,
                      struct kdbus_cmd_match *cmd)
{
  int ret = safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (0 != ret)
    return errno;

  return 0;
}

/**
 * Allocates and initializes kdbus message structure.
 * @param kdbus kdbus object
 * @param size_for_items size of items that will be attached to this message
 * @param flags flags for message
 * @returns initialized kdbus message or NULL if malloc failed
 */
struct kdbus_msg *
_kdbus_new_msg (kdbus_t                *kdbus,
                __u64                   size_for_items,
                __u64                   flags,
                __s64                   priority,
                __u64                   dst_id,
                __u64                   src_id,
                enum kdbus_payload_type payload_type,
                __u64                   cookie,
                __u64                   timeout_ns_or_cookie_reply)
{
  struct kdbus_msg *msg;
  __u64 msg_size = sizeof (struct kdbus_msg) + size_for_items;

  msg = dbus_malloc (msg_size);
  if (NULL == msg)
    return NULL;

  msg->size = msg_size;
  msg->flags = flags;
  msg->priority = priority;
  msg->dst_id = dst_id;
  msg->src_id = src_id;
  msg->payload_type = payload_type;
  msg->cookie = cookie;
  msg->timeout_ns = timeout_ns_or_cookie_reply;

  return msg;
}

void
_kdbus_free_msg (struct kdbus_msg *msg)
{
  dbus_free (msg);
}

int
_kdbus_free_mem (kdbus_t *kdbus, void *mem)
{
  char *base_ptr = kdbus->mmap_ptr;
  char *mem_ptr = (char *)mem;

  return free_by_offset (kdbus, mem_ptr - base_ptr);
}

/**
 * Computes size of items that will be attached to a message.
 *
 * @param kdbus kdbus object
 * @param destination Well-known name or NULL. If NULL, dst_id must be supplied.
 * @param dst_id Numeric id of recipient. Ignored if name is not NULL.
 * @param body_size Size of message body (may be 0).
 * @param use_memfd Flag to build memfd message.
 * @param fds_count Number of file descriptors sent in the message.
 * @returns size in bytes needed for the message object
 */
__u64
_kdbus_compute_msg_items_size (kdbus_t       *kdbus,
                               const char    *destination,
                               __u64          dst_id,
                               __u64          body_size,
                               dbus_bool_t    use_memfd,
                               int            fds_count)
{
  __u64 items_size = 0;

  /*  header */
  items_size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_vec));

  if (use_memfd)
    {
      /* body */
      items_size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_memfd));

      /* footer */
      items_size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_vec));
    }
  else
    {
      __u64 vectors = (body_size + KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE - 1)
                       / KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
      /* subsequent vectors -> parts of body */
      items_size += vectors * KDBUS_ITEM_SIZE (sizeof (struct kdbus_vec));
    }

  if (fds_count > 0)
    items_size += KDBUS_ITEM_SIZE (sizeof (int) * fds_count);

  if (destination)
    items_size += KDBUS_ITEM_SIZE (strlen (destination) + 1);
  else if (KDBUS_DST_ID_BROADCAST == dst_id)
    items_size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_bloom_filter))
                  + kdbus->bloom.size;
  return items_size;
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
 * @param transport transport of the connection
 * @param name the name to request
 * @param flags flags
 * @returns a DBus result code on success, -errno on error
 */
int
_kdbus_request_name (kdbus_t     *kdbus,
                     const char  *name,
                     const __u64  flags)
{
  struct kdbus_cmd *cmd_name;
  size_t len = strlen (name) + 1;
  __u64 size = sizeof (*cmd_name) + KDBUS_ITEM_SIZE (len);
  __u64 flags_kdbus = 0;

  cmd_name = alloca (size);
  cmd_name->size = size;

  if (flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)
    flags_kdbus |= KDBUS_NAME_ALLOW_REPLACEMENT;
  if (!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE))
    flags_kdbus |= KDBUS_NAME_QUEUE;
  if (flags & DBUS_NAME_FLAG_REPLACE_EXISTING)
    flags_kdbus |= KDBUS_NAME_REPLACE_EXISTING;

  cmd_name->flags = flags_kdbus;
  make_item_name (name, &(cmd_name->items[0]));

  _dbus_verbose ("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if (ioctl (kdbus->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name) < 0)
    {
      _dbus_verbose ("error acquiring name '%s': %m, %d\n", name, errno);
      if (errno == EEXIST)
        return DBUS_REQUEST_NAME_REPLY_EXISTS;
      if (errno == EALREADY)
        return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
      return -errno;
    }
  else if ((cmd_name->return_flags & KDBUS_NAME_PRIMARY)
       && !(cmd_name->return_flags & KDBUS_NAME_ACQUIRED))
    return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;

  _dbus_verbose ("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if (cmd_name->return_flags & KDBUS_NAME_IN_QUEUE)
    return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;

  return DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;
}

/**
 *
 * Releases well-known name - the connections resign from the name
 * which can be then assigned to another connection or the connection
 * is being removed from the queue for that name
 *
 * @param name the name to request
 * @param id unique id of the connection for which the name is being released
 * @returns a DBus result code on success, -errno on error
 */
int
_kdbus_release_name (kdbus_t    *kdbus,
                     const char *name)
{
  struct kdbus_cmd *cmd_name;
  size_t len = strlen (name)+1;
  __u64 size = sizeof (*cmd_name) + KDBUS_ITEM_SIZE (len);

  cmd_name = alloca (size);
  cmd_name->size = size;
  cmd_name->flags = 0;
  make_item_name (name, &(cmd_name->items[0]));

  if (ioctl (kdbus->fd, KDBUS_CMD_NAME_RELEASE, cmd_name))
    {
      if ((errno == ESRCH))
        return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
      else if (errno == EADDRINUSE)
        return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
      _dbus_verbose ("error releasing name '%s'. Error: %m, %d\n", name, errno);
      return -errno;
    }

  _dbus_verbose ("Name '%s' released\n", name);

  return DBUS_RELEASE_NAME_REPLY_RELEASED;
}

static int
decode_connection_info (struct kdbus_info *connection_info,
                        struct nameInfo   *pInfo,
                        dbus_bool_t        get_sec_label)
{
  struct kdbus_item *item;

  memset (pInfo, 0, sizeof (*pInfo));

  pInfo->uniqueId = connection_info->id;
  pInfo->flags = connection_info->flags;

  item = connection_info->items;

  while ((uint8_t *)item < ((uint8_t *)connection_info) + connection_info->size)
    {
      switch (item->type)
        {
          case KDBUS_ITEM_PIDS:
            pInfo->processId = item->pids.pid;
            break;
		  case KDBUS_ITEM_CREDS:
			  pInfo->userId = item->creds.uid;
			  break;
          case KDBUS_ITEM_SECLABEL:
              if (get_sec_label)
                {
                  pInfo->sec_label_len = item->size - KDBUS_ITEM_HEADER_SIZE - 1;
                  if (0 != pInfo->sec_label_len)
                    {
                      pInfo->sec_label = dbus_malloc (pInfo->sec_label_len);
                      if (NULL == pInfo->sec_label)
                        return ENOMEM;

                      memcpy (pInfo->sec_label, item->data, pInfo->sec_label_len);
                    }
                }
              break;
        }

      item = KDBUS_ITEM_NEXT (item);
    }
  return 0;
}

static int
process_connection_info_cmd (kdbus_t               *kdbus,
                             struct kdbus_cmd_info *cmd,
                             struct nameInfo       *pInfo,
                             dbus_bool_t            get_sec_label)
{
  int ret;
  struct kdbus_info *kdbus_info;

  if (NULL == cmd)
    return -1;

  ret = safe_ioctl (kdbus->fd, KDBUS_CMD_CONN_INFO, cmd);

  if (ret < 0)
  {
    pInfo->uniqueId = 0;
    return errno;
  }

  kdbus_info = get_from_offset (kdbus, cmd->offset);
  ret = decode_connection_info (kdbus_info,
                                pInfo,
                                get_sec_label);
  if (ret != 0)
    return ret;

  ret = free_by_offset (kdbus, cmd->offset);
  if (ret != 0)
    {
      _dbus_verbose ("kdbus error freeing pool: %d (%m)\n", errno);
      if (get_sec_label)
        {
          free (pInfo->sec_label);
          pInfo->sec_label = NULL;
        }
    }

  dbus_free (cmd);

  return ret;
}

/*
 * In this function either id is equal to 0 AND name is not NULL,
 * or id is greater than 0 AND name is NULL.
 * Thus, condition NULL != name is equivalent to 0 == id.
 */
static struct kdbus_cmd_info *
prepare_connection_info_cmd (__u64          id,
                             const char    *name,
                             dbus_bool_t    get_sec_label)
{
  struct kdbus_cmd_info *cmd;
  __u64 size = sizeof (*cmd);

  if (NULL != name)
    size += KDBUS_ITEM_SIZE (strlen (name) + 1);

  cmd = dbus_malloc (size);
  if (NULL == cmd)
    return NULL;

  cmd->size = size;
  cmd->id = id;
  if (NULL != name)
    make_item_name (name, &(cmd->items[0]));

  cmd->attach_flags = KDBUS_ATTACH_CREDS | KDBUS_ATTACH_PIDS;
  if (get_sec_label)
    cmd->attach_flags |= KDBUS_ATTACH_SECLABEL;

  cmd->flags = 0;

  return cmd;
}

/**
 * Gets connection info for the given unique id.
 *
 * @param kdbus kdbus object
 * @param id unique id to query for
 * @param get_sec_label #TRUE if sec_label field in pInfo should be filled
 * @param pInfo nameInfo structure address to store info about the name
 * @return 0 on success, errno if failed
 *
 * @note If you specify #TRUE in get_sec_label param, you must free
 * pInfo.sec_label with dbus_free() after use.
 */
int
_kdbus_connection_info_by_id (kdbus_t         *kdbus,
                              __u64            id,
                              dbus_bool_t      get_sec_label,
                              struct nameInfo *pInfo)
{
  struct kdbus_cmd_info *cmd = prepare_connection_info_cmd (id, NULL, get_sec_label);

  return process_connection_info_cmd (kdbus, cmd, pInfo, get_sec_label);
}

/**
 * Gets connection info for the given name
 *
 * @param kdbus kdbus object
 * @param name name to query for
 * @param get_sec_label #TRUE if sec_label field in pInfo should be filled
 * @param pInfo nameInfo structure address to store info about the name
 * @return 0 on success, errno if failed
 *
 * @note If you specify #TRUE in get_sec_label param, you must free
 * pInfo.sec_label with dbus_free() after use.
 */
int
_kdbus_connection_info_by_name (kdbus_t         *kdbus,
                                const char      *name,
                                dbus_bool_t      get_sec_label,
                                struct nameInfo *pInfo)
{
  struct kdbus_cmd_info *cmd;

  /* if name starts with ":1." it is a unique name and should be send as number */
  if ((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))
  {
    return _kdbus_connection_info_by_id (kdbus,
                                         strtoull (&name[3], NULL, 10),
                                         get_sec_label,
                                         pInfo);
  }

  cmd = prepare_connection_info_cmd (0, name, get_sec_label);

  return process_connection_info_cmd (kdbus, cmd, pInfo, get_sec_label);
}

/*
 * Removes match rule in kdbus on behalf of sender of the message
 * @param kdbus kdbus object
 * @param cookie cookie of the rules to be removed
 */
int
_kdbus_remove_match (kdbus_t    *kdbus,
                     __u64       cookie)
{
  struct kdbus_cmd_match cmd;

  VALGRIND_MAKE_MEM_DEFINED (&cmd, sizeof (cmd));

  cmd.cookie = cookie;
  cmd.size = sizeof (struct kdbus_cmd_match);
  cmd.flags = 0;

  if (safe_ioctl (kdbus->fd, KDBUS_CMD_MATCH_REMOVE, &cmd) != 0)
    return errno;

  return 0;
}

/************************* BLOOM FILTERS ***********************/

/*
 * Macros for SipHash algorithm
 */
#define ROTL(x,b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)         \
    (p)[0] = (unsigned char)((v)      ); (p)[1] = (unsigned char)((v) >>  8); \
    (p)[2] = (unsigned char)((v) >> 16); (p)[3] = (unsigned char)((v) >> 24);

#define U64TO8_LE(p, v)         \
  U32TO8_LE((p),     (uint32_t)((v)      ));   \
  U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p) \
  (((uint64_t)((p)[0])      ) | \
   ((uint64_t)((p)[1]) <<  8) | \
   ((uint64_t)((p)[2]) << 16) | \
   ((uint64_t)((p)[3]) << 24) | \
   ((uint64_t)((p)[4]) << 32) | \
   ((uint64_t)((p)[5]) << 40) | \
   ((uint64_t)((p)[6]) << 48) | \
   ((uint64_t)((p)[7]) << 56))

#define SIPROUND            \
  do {              \
    v0 += v1; v1=ROTL(v1,13); v1 ^= v0; v0=ROTL(v0,32); \
    v2 += v3; v3=ROTL(v3,16); v3 ^= v2;     \
    v0 += v3; v3=ROTL(v3,21); v3 ^= v0;     \
    v2 += v1; v1=ROTL(v1,17); v1 ^= v2; v2=ROTL(v2,32); \
  } while (0)


/*
 * Hash keys for bloom filters
 */
static const unsigned char hash_keys[8][16] =
{
  {0xb9,0x66,0x0b,0xf0,0x46,0x70,0x47,0xc1,0x88,0x75,0xc4,0x9c,0x54,0xb9,0xbd,0x15},
  {0xaa,0xa1,0x54,0xa2,0xe0,0x71,0x4b,0x39,0xbf,0xe1,0xdd,0x2e,0x9f,0xc5,0x4a,0x3b},
  {0x63,0xfd,0xae,0xbe,0xcd,0x82,0x48,0x12,0xa1,0x6e,0x41,0x26,0xcb,0xfa,0xa0,0xc8},
  {0x23,0xbe,0x45,0x29,0x32,0xd2,0x46,0x2d,0x82,0x03,0x52,0x28,0xfe,0x37,0x17,0xf5},
  {0x56,0x3b,0xbf,0xee,0x5a,0x4f,0x43,0x39,0xaf,0xaa,0x94,0x08,0xdf,0xf0,0xfc,0x10},
  {0x31,0x80,0xc8,0x73,0xc7,0xea,0x46,0xd3,0xaa,0x25,0x75,0x0f,0x9e,0x4c,0x09,0x29},
  {0x7d,0xf7,0x18,0x4b,0x7b,0xa4,0x44,0xd5,0x85,0x3c,0x06,0xe0,0x65,0x53,0x96,0x6d},
  {0xf2,0x77,0xe9,0x6f,0x93,0xb5,0x4e,0x71,0x9a,0x0c,0x34,0x88,0x39,0x25,0xbf,0x35}
};

/*
 * SipHash algorithm
 */
static void
_g_siphash24 (unsigned char       out[8],
              const void         *_in,
              size_t              inlen,
              const unsigned char k[16])
{
  uint64_t v0 = 0x736f6d6570736575ULL;
  uint64_t v1 = 0x646f72616e646f6dULL;
  uint64_t v2 = 0x6c7967656e657261ULL;
  uint64_t v3 = 0x7465646279746573ULL;
  uint64_t b;
  uint64_t k0 = U8TO64_LE (k);
  uint64_t k1 = U8TO64_LE (k + 8);
  uint64_t m;
  const unsigned char *in = _in;
  const unsigned char *end = in + inlen - (inlen % sizeof (uint64_t));
  const int left = inlen & 7;
  b = ((uint64_t) inlen) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  for (; in != end; in += 8)
    {
      m = U8TO64_LE (in);
      v3 ^= m;
      SIPROUND;
      SIPROUND;
      v0 ^= m;
    }

  switch (left)
    {
      case 7: b |= ((uint64_t) in[6]) << 48;
      case 6: b |= ((uint64_t) in[5]) << 40;
      case 5: b |= ((uint64_t) in[4]) << 32;
      case 4: b |= ((uint64_t) in[3]) << 24;
      case 3: b |= ((uint64_t) in[2]) << 16;
      case 2: b |= ((uint64_t) in[1]) <<  8;
      case 1: b |= ((uint64_t) in[0]); break;
      case 0: break;
    }

  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;

  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  b = v0 ^ v1 ^ v2  ^ v3;
  U64TO8_LE (out, b);
}

void
_kdbus_bloom_add_data (kdbus_t            *kdbus,
                       kdbus_bloom_data_t *bloom_data,
                       const void         *data,
                       size_t              data_size)
{
  unsigned char hash[8];
  uint64_t bit_num;
  unsigned int bytes_num = 0;
  unsigned int cnt_1, cnt_2;
  unsigned int hash_index = 0;

  unsigned int c = 0;
  uint64_t p = 0;

  bit_num = kdbus->bloom.size * 8;

  if (bit_num > 1)
    bytes_num = ((__builtin_clzll (bit_num) ^ 63U) + 7) / 8;

  for (cnt_1 = 0; cnt_1 < kdbus->bloom.n_hash; cnt_1++)
    {
      for (cnt_2 = 0, hash_index = 0; cnt_2 < bytes_num; cnt_2++)
        {
          if (c <= 0)
            {
              _g_siphash24 (hash, data, data_size, hash_keys[hash_index++]);
              c += 8;
            }

          p = (p << 8ULL) | (uint64_t) hash[8 - c];
          c--;
        }

      p &= bit_num - 1;
      bloom_data[p >> 6] |= 1ULL << (p & 63);
    }
}
