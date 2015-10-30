/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* kdbus-common.h  kdbus related utils for daemon and libdbus
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

#ifndef KDBUS_COMMON_H_
#define KDBUS_COMMON_H_

#include <dbus/dbus-types.h>
#include <dbus/dbus-transport.h>
#include "dbus-signals.h"
#include "kdbus.h"

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)

#define KDBUS_ITEM_HEADER_SIZE          offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8(KDBUS_ITEM_HEADER_SIZE + (s))
#define KDBUS_ITEM_NEXT(item) \
        (typeof(item))(((uint8_t *)item) + KDBUS_ALIGN8((item)->size))
#define KDBUS_ITEM_FOREACH(item, head, first)                           \
        for (item = (head)->first;                                      \
             (uint8_t *)(item) < (uint8_t *)(head) + (head)->size;      \
             item = KDBUS_ITEM_NEXT(item))

#define KDBUS_MSG_MAX_PAYLOAD_VEC_SIZE  0x00200000              /* maximum size of message header and items */

struct nameInfo
{
  __u64 uniqueId;
  __u64 flags;
  __u64 userId;
  __u64 processId;
  __u32 sec_label_len;
  char *sec_label;
};

typedef struct kdbus_t kdbus_t;

kdbus_t *   _kdbus_new                             (void);
void        _kdbus_free                            (kdbus_t *kdbus);

int         _kdbus_open                            (kdbus_t *kdbus, const char *path);
int         _kdbus_close                           (kdbus_t *kdbus);

int         _kdbus_hello                           (kdbus_t       *kdbus,
                                                    dbus_uint64_t  flags,
                                                    dbus_uint64_t  attach_flags_send,
                                                    dbus_uint64_t  attach_flags_recv,
                                                    dbus_uint64_t  pool_size,
                                                    const char    *activator_name,
                                                    const char    *connection_name);

int         _kdbus_send                            (kdbus_t           *kdbus,
                                                    dbus_uint64_t      flags,
                                                    struct kdbus_msg  *msg,
                                                    struct kdbus_msg **msg_reply);

int         _kdbus_recv                            (kdbus_t           *kdbus,
                                                    dbus_uint64_t      flags,
                                                    dbus_int64_t       priority,
                                                    struct kdbus_msg **msg);

int         _kdbus_list                            (kdbus_t            *kdbus,
                                                    dbus_uint64_t       flags,
                                                    struct kdbus_info **name_list,
                                                    dbus_uint64_t      *list_size);

int         _kdbus_add_match_name_change           (kdbus_t *kdbus,
                                                    dbus_uint64_t flags,
                                                    dbus_uint64_t cookie,
                                                    dbus_uint64_t old_id,
                                                    dbus_uint64_t old_id_flags,
                                                    dbus_uint64_t new_id,
                                                    dbus_uint64_t new_id_flags);

int         _kdbus_add_match_id_change             (kdbus_t *kdbus,
                                                    dbus_uint64_t flags,
                                                    dbus_uint64_t cookie,
                                                    dbus_uint64_t id,
                                                    dbus_uint64_t id_flags);

int         _kdbus_add_match                      (kdbus_t *kdbus,
                                                   struct kdbus_cmd_match *cmd);

int         _kdbus_connection_info_by_name         (kdbus_t         *kdbus,
                                                    const char      *name,
                                                    dbus_bool_t      get_sec_label,
                                                    struct nameInfo *pInfo);

int         _kdbus_connection_info_by_id           (kdbus_t         *kdbus,
                                                    dbus_uint64_t    id,
                                                    dbus_bool_t      get_sec_label,
                                                    struct nameInfo *pInfo);

dbus_uint64_t      _kdbus_compute_msg_items_size   (kdbus_t       *kdbus,
                                                    const char    *destination,
                                                    dbus_uint64_t  dst_id,
                                                    dbus_uint64_t  body_size,
                                                    dbus_bool_t    use_memfd,
                                                    int            fds_count);

struct kdbus_msg * _kdbus_new_msg                  (kdbus_t                *kdbus,
                                                    dbus_uint64_t           size_for_items,
                                                    dbus_uint64_t           flags,
                                                    dbus_int64_t            priority,
                                                    dbus_uint64_t           dst_id,
                                                    dbus_uint64_t           src_id,
                                                    enum kdbus_payload_type payload_type,
                                                    dbus_uint64_t           cookie,
                                                    dbus_uint64_t           timeout_ns_or_cookie_reply);

void               _kdbus_free_msg                 (struct kdbus_msg *msg);

struct kdbus_cmd_match *_kdbus_new_cmd_match       (kdbus_t       *kdbus,
                                                    dbus_uint64_t  items_size,
                                                    dbus_uint64_t  flags,
                                                    dbus_uint64_t  cookie);

void               _kdbus_free_cmd_match           (struct kdbus_cmd_match *cmd);

int                _kdbus_free_mem                 (kdbus_t *kdbus, void *mem);

struct kdbus_item * _kdbus_item_add_string         (struct kdbus_item *item,
                                                    dbus_uint64_t      item_type,
                                                    const char        *item_string,
                                                    dbus_uint64_t      item_string_size);

struct kdbus_item * _kdbus_item_add_payload_memfd  (struct kdbus_item *item,
                                                    dbus_uint64_t      start,
                                                    dbus_uint64_t      size,
                                                    int                fd);

struct kdbus_item * _kdbus_item_add_payload_vec    (struct kdbus_item *item,
                                                    dbus_uint64_t      size,
                                                    dbus_uint64_t      address_or_offset);

struct kdbus_item * _kdbus_item_add_fds            (struct kdbus_item *item,
                                                    const int         *fds,
                                                    int                fds_count);

struct kdbus_item * _kdbus_item_add_bloom_filter   (struct kdbus_item          *item,
                                                    dbus_uint64_t               data_size,
                                                    struct kdbus_bloom_filter **out_ptr);

struct kdbus_item * _kdbus_item_add_name_change    (struct kdbus_item *item,
                                                    dbus_uint64_t old_id,
                                                    dbus_uint64_t old_id_flags,
                                                    dbus_uint64_t new_id,
                                                    dbus_uint64_t new_id_flags);

struct kdbus_item * _kdbus_item_add_id_add         (struct kdbus_item *item,
                                                    dbus_uint64_t      id,
                                                    dbus_uint64_t      id_flags);

struct kdbus_item * _kdbus_item_add_id             (struct kdbus_item *item,
                                                    dbus_uint64_t      id);

struct kdbus_item * _kdbus_item_add_bloom_mask     (struct kdbus_item *item,
                                                    dbus_uint64_t     *bloom,
                                                    dbus_uint64_t      bloom_size);

int         request_kdbus_name                     (DBusTransport* transport, const char *name, const __u64 flags);
int         release_kdbus_name                     (DBusTransport* transport, const char *name);

dbus_bool_t kdbus_remove_match          (DBusTransport *transport, DBusList *rules, const char *sender,
                                             MatchRule *rule_to_remove, DBusError *error);

/** temporary accessors - to delete soon */
int _kdbus_fd (kdbus_t *kdbus);
void *_kdbus_mmap_ptr (kdbus_t *kdbus);
dbus_uint64_t _kdbus_id (kdbus_t *kdbus);
char *_kdbus_bus_id (kdbus_t *kdbus);
dbus_uint64_t _kdbus_bus_id_size (void);
struct kdbus_bloom_parameter *_kdbus_bloom (kdbus_t *kdbus);

#endif /* KDBUS_COMMON_H_ */
