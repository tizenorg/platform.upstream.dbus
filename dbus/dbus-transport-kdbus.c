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
#include <kdbus.h>
#include "dbus-errors.h"
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>

//todo poniższe do wywalenia po zaimplementowaniu vtable (_dbus_transport_new_for_socket)
#include "dbus-transport-socket.h"

int _dbus_connect_kdbus (const char *path, DBusError *error);
DBusTransport* _dbus_transport_new_for_kdbus (const char *path, DBusError *error);


/**
 * Creates a connection to the kdbus bus
  *
 * This will set FD_CLOEXEC for the socket returned.
 *
 * @param path the path to UNIX domain socket
 * @param error return location for error code
 * @returns connection file descriptor or -1 on error
 */
int _dbus_connect_kdbus (const char *path, DBusError *error)
{
	int fd;

	_DBUS_ASSERT_ERROR_IS_CLEAR (error);
	_dbus_verbose ("connecting to kdbus bus %s\n", path);

	fd = open(path, O_RDWR|O_CLOEXEC|O_NONBLOCK); //[RP] | O_NONBLOCK added here, in dbus added separately in section commented out below
	if (fd < 0)
	{
		dbus_set_error(error, _dbus_error_from_errno (errno), "Failed to open file descriptor: %s", _dbus_strerror (errno));
		_DBUS_ASSERT_ERROR_IS_SET(error);
		return -1;  //[RP] not needed here if commented block below is removed
	}

	/*if (!_dbus_set_fd_nonblocking (fd, error))
    {
		_DBUS_ASSERT_ERROR_IS_SET (error);
		_dbus_close (fd, NULL);
		return -1;
    }*/

	return fd;
}


/**
 * Creates a new transport for kdbus.
 * This creates a client-side of a transport.
 *
 * @param path the path to the domain socket.
 * @param error address where an error can be returned.
 * @returns a new transport, or #NULL on failure.
 */
DBusTransport* _dbus_transport_new_for_kdbus (const char *path, DBusError *error)
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

	if (!_dbus_string_append (&address, path))
    {
		dbus_set_error (error, DBUS_ERROR_NO_MEMORY, NULL);
		goto failed_0;
    }

	fd = _dbus_connect_kdbus (path, error);
//	fd = _dbus_connect_unix_socket (path, error);
	if (fd < 0)
    {
		_DBUS_ASSERT_ERROR_IS_SET (error);
		goto failed_0;
    }

	_dbus_verbose ("Successfully connected to kdbus bus %s\n", path);

	transport = _dbus_transport_new_for_socket (fd, NULL, &address);  //todo
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
 * Opens kdbus transport.
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

dbus_bool_t bus_register_kdbus(char** unique_name, DBusConnection *connection, DBusError *error)
{
	dbus_bool_t retval = TRUE;
	char name[18];
	struct kdbus_cmd_hello hello;
	int fd;

	memset(&hello, 0, sizeof(hello));
	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD |
			   KDBUS_HELLO_ATTACH_COMM |
			   KDBUS_HELLO_ATTACH_EXE |
			   KDBUS_HELLO_ATTACH_CMDLINE |
			   KDBUS_HELLO_ATTACH_CAPS |
			   KDBUS_HELLO_ATTACH_CGROUP |
			   KDBUS_HELLO_ATTACH_SECLABEL |
			   KDBUS_HELLO_ATTACH_AUDIT;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = (16 * 1024LU * 1024LU);  //todo was: #define POOL_SIZE

	if(!dbus_connection_get_socket(connection, &fd))
	{
		dbus_set_error (error, "failed to get fd for connection", NULL);
		return FALSE;
	}
	if (ioctl(fd, KDBUS_CMD_HELLO, &hello))
	{
		dbus_set_error(error,_dbus_error_from_errno (errno), "Failed to send  hello: %s", _dbus_strerror (errno));
		return FALSE;
	}

	_dbus_verbose("-- Our peer ID is: %llu\n", (unsigned long long)hello.id);  //todo [RP] can be removed after development
	sprintf(name, "%llx", (unsigned long long)hello.id);
	*unique_name = _dbus_strdup(name);
	if (*unique_name == NULL)
	{
	  _DBUS_SET_OOM (error);
	  return FALSE;
	}

	return retval;
}
