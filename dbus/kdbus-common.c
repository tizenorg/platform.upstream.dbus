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
  char bus_id[sizeof(((struct kdbus_cmd_hello *)(0))->id128)];  /**< id of the bus */
  struct kdbus_bloom_parameter bloom;                         /**< bloom parameters*/
};

/** temporary accessors - to delete soon */
int _kdbus_fd (kdbus_t *kdbus) { return kdbus->fd; }
void *_kdbus_mmap_ptr (kdbus_t *kdbus) { return kdbus->mmap_ptr; }
dbus_uint64_t _kdbus_id (kdbus_t *kdbus) { return kdbus->id; }
char *_kdbus_bus_id (kdbus_t *kdbus) { return kdbus->bus_id; }
dbus_uint64_t _kdbus_bus_id_size (void) { return sizeof(((struct kdbus_t *)(0))->bus_id); }
struct kdbus_bloom_parameter *_kdbus_bloom (kdbus_t *kdbus) { return &kdbus->bloom; }



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

  cmd.size = sizeof (cmd);
  cmd.offset = offset;
  cmd.flags = 0;

  if (safe_ioctl (kdbus->fd, KDBUS_CMD_FREE, &cmd )!= 0)
    return errno;

  return 0;
}

static void make_item_name(const char *name, struct kdbus_item *item)
{
  size_t len = strlen(name) + 1;
  item->size = KDBUS_ITEM_HEADER_SIZE + len;
  item->type = KDBUS_ITEM_NAME;

  memcpy(item->str, name, len);
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
                        dbus_uint64_t      item_type,
                        const char        *item_string,
                        dbus_uint64_t      item_string_size)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + item_string_size;
  item->type = item_type;
  memcpy (item->str, item_string, item_string_size);
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_payload_memfd (struct kdbus_item *item,
                               dbus_uint64_t      start,
                               dbus_uint64_t      size,
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
                             dbus_uint64_t      size,
                             dbus_uint64_t      address_or_offset)
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
  item->size = KDBUS_ITEM_HEADER_SIZE + fds_count * sizeof (int);
  memcpy (item->fds, fds, fds_count * sizeof (int));
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_bloom_filter (struct kdbus_item          *item,
                              dbus_uint64_t               data_size,
                              struct kdbus_bloom_filter **out_ptr)
{
  item->type = KDBUS_ITEM_BLOOM_FILTER;
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_bloom_filter) + data_size;
  *out_ptr = &item->bloom_filter;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_name_change (struct kdbus_item *item,
                             dbus_uint64_t old_id,
                             dbus_uint64_t old_id_flags,
                             dbus_uint64_t new_id,
                             dbus_uint64_t new_id_flags)
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
                        dbus_uint64_t      id,
                        dbus_uint64_t      id_flags)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_notify_id_change);
  item->type = KDBUS_ITEM_ID_ADD;
  item->id_change.id = id;
  item->id_change.flags = id_flags;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_id (struct kdbus_item *item,
                    dbus_uint64_t      id)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + sizeof (struct kdbus_notify_id_change);
  item->type = KDBUS_ITEM_ID;
  item->id = id;
  return KDBUS_ITEM_NEXT (item);
}

struct kdbus_item *
_kdbus_item_add_bloom_mask (struct kdbus_item *item,
                            dbus_uint64_t     *bloom,
                            dbus_uint64_t      bloom_size)
{
  item->size = KDBUS_ITEM_HEADER_SIZE + bloom_size;
  item->type = KDBUS_ITEM_BLOOM_MASK;
  memcpy (item->data, bloom, bloom_size);
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
_kdbus_hello (kdbus_t       *kdbus,
              dbus_uint64_t  flags,
              dbus_uint64_t  attach_flags_send,
              dbus_uint64_t  attach_flags_recv,
              dbus_uint64_t  pool_size,
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
             dbus_uint64_t      flags,
             struct kdbus_msg  *msg,
             struct kdbus_msg **msg_reply)
{
  struct kdbus_cmd_send cmd;

  cmd.size = sizeof(cmd);
  cmd.msg_address = (__u64)msg;
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
             dbus_uint64_t      flags,
             dbus_int64_t       priority,
             struct kdbus_msg **msg)
{
  struct kdbus_cmd_recv cmd;

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
             dbus_uint64_t       flags,
             struct kdbus_info **name_list,
             dbus_uint64_t      *list_size)
{
  struct kdbus_cmd_list cmd;

  cmd.size = sizeof (cmd);
  cmd.flags = flags;

  if (-1 == safe_ioctl (kdbus->fd, KDBUS_CMD_LIST, &cmd))
    return errno;

  *name_list = get_from_offset (kdbus, cmd.offset);
  *list_size = cmd.list_size;

  return 0;
}

struct kdbus_cmd_match *
_kdbus_new_cmd_match (kdbus_t       *kdbus,
                      dbus_uint64_t  items_size,
                      dbus_uint64_t  flags,
                      dbus_uint64_t  cookie)
{
  struct kdbus_cmd_match *cmd;
  dbus_uint64_t cmd_size = sizeof (*cmd) + items_size;
  cmd = dbus_malloc (cmd_size);
  if (NULL == cmd)
    return NULL;

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
                              dbus_uint64_t flags,
                              dbus_uint64_t cookie,
                              dbus_uint64_t old_id,
                              dbus_uint64_t old_id_flags,
                              dbus_uint64_t new_id,
                              dbus_uint64_t new_id_flags)
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
                            dbus_uint64_t flags,
                            dbus_uint64_t cookie,
                            dbus_uint64_t id,
                            dbus_uint64_t id_flags)
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
                dbus_uint64_t           size_for_items,
                dbus_uint64_t           flags,
                dbus_int64_t            priority,
                dbus_uint64_t           dst_id,
                dbus_uint64_t           src_id,
                enum kdbus_payload_type payload_type,
                dbus_uint64_t           cookie,
                dbus_uint64_t           timeout_ns_or_cookie_reply)
{
  struct kdbus_msg *msg;
  dbus_uint64_t msg_size = sizeof (struct kdbus_msg) + size_for_items;

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
dbus_uint64_t
_kdbus_compute_msg_items_size (kdbus_t       *kdbus,
                               const char    *destination,
                               dbus_uint64_t  dst_id,
                               dbus_uint64_t  body_size,
                               dbus_bool_t    use_memfd,
                               int            fds_count)
{
  dbus_uint64_t items_size = 0;

  if (use_memfd)
    {
      items_size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_memfd));
    }
  else
    {
      dbus_uint64_t vectors = (body_size + KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE - 1)
                              / KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE;
      /* 1st vector -> for header */
      items_size += KDBUS_ITEM_SIZE (sizeof (struct kdbus_vec));
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
  size_t len = strlen(name) + 1;

  __u64 size = sizeof(*cmd_name) + KDBUS_ITEM_SIZE(len);
  __u64 flags_kdbus = 0;

  cmd_name = alloca(size);
  cmd_name->size = size;

  if(flags & DBUS_NAME_FLAG_ALLOW_REPLACEMENT)
    flags_kdbus |= KDBUS_NAME_ALLOW_REPLACEMENT;
  if(!(flags & DBUS_NAME_FLAG_DO_NOT_QUEUE))
    flags_kdbus |= KDBUS_NAME_QUEUE;
  if(flags & DBUS_NAME_FLAG_REPLACE_EXISTING)
    flags_kdbus |= KDBUS_NAME_REPLACE_EXISTING;

  cmd_name->flags = flags_kdbus;
  make_item_name(name, &(cmd_name->items[0]));

  _dbus_verbose("Request name - flags sent: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if (ioctl(kdbus->fd, KDBUS_CMD_NAME_ACQUIRE, cmd_name) < 0)
    {
      _dbus_verbose ("error acquiring name '%s': %m, %d\n", name, errno);
      if(errno == EEXIST)
        return DBUS_REQUEST_NAME_REPLY_EXISTS;
      if(errno == EALREADY)
        return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
      return -errno;
    }
  else if ((cmd_name->return_flags & KDBUS_NAME_PRIMARY)
       && !(cmd_name->return_flags & KDBUS_NAME_ACQUIRED))
    return DBUS_REQUEST_NAME_REPLY_ALREADY_OWNER;

  _dbus_verbose("Request name - received flag: 0x%llx       !!!!!!!!!\n", cmd_name->flags);

  if(cmd_name->return_flags & KDBUS_NAME_IN_QUEUE)
    return DBUS_REQUEST_NAME_REPLY_IN_QUEUE;

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
int
_kdbus_release_name (kdbus_t    *kdbus,
                     const char *name)
{
  struct kdbus_cmd *cmd_name;

  size_t len = strlen(name)+1;
  __u64 size = sizeof(*cmd_name) + KDBUS_ITEM_SIZE(len);

  cmd_name = alloca(size);
  cmd_name->size = size;
  cmd_name->flags = 0;
  make_item_name(name, &(cmd_name->items[0]));

  if (ioctl(kdbus->fd, KDBUS_CMD_NAME_RELEASE, cmd_name))
    {
      if((errno == ESRCH))
        return DBUS_RELEASE_NAME_REPLY_NON_EXISTENT;
      else if (errno == EADDRINUSE)
        return DBUS_RELEASE_NAME_REPLY_NOT_OWNER;
      _dbus_verbose ("error releasing name '%s'. Error: %m, %d\n", name, errno);
      return -errno;
    }

  _dbus_verbose("Name '%s' released\n", name);

  return DBUS_RELEASE_NAME_REPLY_RELEASED;
}

static int
decode_connection_info (struct kdbus_info *connection_info,
                        struct nameInfo   *pInfo,
                        dbus_bool_t        get_sec_label)
{
  struct kdbus_item *item;

  memset (pInfo, 0, sizeof(*pInfo));

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
      _dbus_verbose("kdbus error freeing pool: %d (%m)\n", errno);
      if (get_sec_label)
        {
          free(pInfo->sec_label);
          pInfo->sec_label = NULL;
        }
    }

  dbus_free (cmd);

  return ret;
}

static struct kdbus_cmd_info *
prepare_connection_info_cmd (dbus_uint64_t  id,
                             const char    *name,
                             dbus_bool_t    get_sec_label)
{
  struct kdbus_cmd_info *cmd;
  dbus_uint64_t size = sizeof(*cmd);
  if (NULL != name)
    {
      size += KDBUS_ITEM_SIZE (strlen (name) + 1);
    }
  cmd = dbus_malloc (size);
  if (NULL == cmd)
    return NULL;

  cmd->size = size;
  cmd->id = id;
  if (0 == id)
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
                              dbus_uint64_t    id,
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
  if((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))
  {
    return _kdbus_connection_info_by_id (kdbus,
                                         strtoull(&name[3], NULL, 10),
                                         get_sec_label,
                                         pInfo);
  }

  cmd = prepare_connection_info_cmd (0, name, get_sec_label);

  return process_connection_info_cmd (kdbus, cmd, pInfo, get_sec_label);
}

/**
 * Opposing to dbus, in kdbus removes all match rules with given
 * cookie, which in this implementation is equal to uniqe id.
 *
 * @param kdbus kdbus object
 * @param id connection id for which rules are to be removed
 * @param cookie cookie of the rules to be removed
 */
static dbus_bool_t
remove_match_kdbus (kdbus_t *kdbus,
                    __u64    cookie)
{
  struct kdbus_cmd_match cmd;

  cmd.cookie = cookie;
  cmd.size = sizeof(struct kdbus_cmd_match);
  cmd.flags = 0;

  if(ioctl (kdbus->fd, KDBUS_CMD_MATCH_REMOVE, &cmd))
    {
      _dbus_verbose ("Failed removing match rule %llu, error: %d, %m\n", cookie, errno);
      return FALSE;
    }
  else
    {
      _dbus_verbose ("Match rule %llu removed correctly.\n", cookie);
      return TRUE;
    }
}

/*
 *  Removes match rule in kdbus on behalf of sender of the message
 */
dbus_bool_t
_kdbus_remove_match (kdbus_t    *kdbus,
                     DBusList   *rules,
                     const char *sender,
                     MatchRule  *rule_to_remove,
                     DBusError  *error)
{
  __u64 cookie = 0;
  DBusList *link = NULL;

  if (rules != NULL)
    {
      /* we traverse backward because bus_connection_remove_match_rule()
       * removes the most-recently-added rule
       */
      link = _dbus_list_get_last_link (&rules);
      while (link != NULL)
        {
          MatchRule *rule;
          DBusList *prev;

          rule = link->data;
          prev = _dbus_list_get_prev_link (&rules, link);

          if (match_rule_equal_lib (rule, rule_to_remove))
            {
              cookie = match_rule_get_cookie(rule);
              break;
            }

          link = prev;
        }
    }

  if(cookie == 0)
    {
      dbus_set_error (error, DBUS_ERROR_MATCH_RULE_NOT_FOUND,
                      "The given match rule wasn't found and can't be removed");
      return FALSE;
    }

  if(!remove_match_kdbus (kdbus, cookie))
    {
      dbus_set_error (error, _dbus_error_from_errno (errno), "Could not remove match rule");
      return FALSE;
    }

  return TRUE;
}
