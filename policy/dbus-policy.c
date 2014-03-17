/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-policy.c - helper library for fine-grained userspace policy handling
 *
 * Copyright (C) 2014 Samsung Electronics
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Author: Lukasz Skalski <l.skalski@samsung.com>
 *
 */

#include <config.h>
#include <stdio.h>

#include "../bus/policy.h"
#include "../bus/config-parser.h"
#include "dbus-policy.h"


/*
 * dbus_policy_check_can_send():
 *
 */
int dbus_policy_check_can_send (void        *client_policy,
                                int          message_type,
                                const char  *destination,
                                const char  *path,
                                const char  *interface,
                                const char  *member,
                                const char  *error_name,
                                int          reply_serial,
                                int          requested_reply)
{
  dbus_bool_t requested_reply_bool = FALSE;

  if (requested_reply)
    requested_reply_bool = TRUE;

  if (!bus_policy_check_can_send ((BusClientPolicy*)client_policy,
                                  requested_reply_bool,
                                  message_type,
                                  destination,
                                  path,
                                  interface,
                                  member,
                                  error_name,
                                  reply_serial))
    return 0;
  else
    return 1;
}


/*
 * dbus_policy_check_can_recv():
 *
 */
int dbus_policy_check_can_recv (void        *client_policy,
                                int          message_type,
                                const char  *sender,
                                const char  *path,
                                const char  *interface,
                                const char  *member,
                                const char  *error_name,
                                int          reply_serial,
                                int          requested_reply)
{
  dbus_bool_t requested_reply_bool = FALSE;

  if (requested_reply)
    requested_reply_bool = TRUE;

  if (!bus_policy_check_can_receive ((BusClientPolicy*)client_policy,
                                     requested_reply_bool,
                                     message_type,
                                     sender,
                                     path,
                                     interface,
                                     member,
                                     error_name,
                                     reply_serial))
    return 0;
  else
    return 1;
}


/*
 * dbus_policy_check_can_own():
 *
 */
int dbus_policy_check_can_own (void       *client_policy,
                               const char *service_name)
{
  DBusString dbus_service_name;
  _dbus_string_init_const (&dbus_service_name, service_name);

  if(!bus_client_policy_check_can_own ((BusClientPolicy*)client_policy,
                                        &dbus_service_name))
    return 0;
  else
    return 1;
}


/*
 * dbus_policy_print_rules():
 *
 */
void dbus_policy_print_rules (void *client)
{
  bus_client_policy_print ((BusClientPolicy*)client);
}


/*
 * dbus_policy_init():
 *
 */
void *dbus_policy_init (unsigned int bus_type)
{
  BusConfigParser *parser;
  BusClientPolicy *client;
  BusPolicy       *policy;

  DBusString config_file;
  DBusError  error;

  dbus_error_init (&error);

  if (!_dbus_string_init (&config_file))
    goto failed;

  if (bus_type == 1)
    _dbus_string_append (&config_file, SYSTEM_BUS_CONF_FILE);
  else if (bus_type == 2)
    _dbus_string_append (&config_file, SESSION_BUS_CONF_FILE);
  else
    goto failed;

  /*
   * BusConfigParser
   */
  parser = bus_config_load (&config_file, TRUE, NULL, &error);
  if (parser == NULL)
    goto failed;

  /*
   * BusPolicy
   */
  policy = bus_config_parser_steal_policy (parser);
  if (policy == NULL)
    goto failed;

  /*
   * BusClientPolicy
   */
  client = bus_policy_create_client_policy (policy, NULL, &error);
  if (client == NULL)
    goto failed;

  /*
   * Free unused memory
   */
  bus_config_parser_unref (parser);
  bus_policy_unref (policy);

  return client;

failed:
  return NULL;
}


/*
 * dbus_policy_free():
 *
 */
void dbus_policy_free (void *client)
{
  bus_client_policy_unref ((BusClientPolicy*)client);
}
