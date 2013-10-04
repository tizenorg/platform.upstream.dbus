//gcc -o server serwer.c -Wall -g -O0 `pkg-config --cflags --libs dbus-1`

#include <dbus/dbus.h>
#include <stdio.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DBUS_NAME "com.samsung.pingpong"
#define DBUS_PATH "/com/samsung/pingpong"
#define DBUS_IFACE "com.samsung.pingpong"

DBusConnection *dbus_conn;
DBusObjectPathVTable *dbus_vtable;

static DBusHandlerResult
handler_function(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	DBusMessage *reply;

	DBusError error;
	dbus_error_init(&error);

	char * ping;

	if (!dbus_message_get_args ( msg,
					&error,
					DBUS_TYPE_STRING,
					&ping,
					DBUS_TYPE_INVALID)) 
	{
		fprintf(stderr, "Error - Invalid ping message!");
		reply = dbus_message_new_error(msg, "com.misiek.pingpong.PingError","ping message corrupted");
	} else {
		printf ("Received from client%s\n", ping);
		reply = dbus_message_new_method_return(msg);
		dbus_message_append_args (reply, DBUS_TYPE_STRING, &ping, DBUS_TYPE_INVALID);
	}
	dbus_connection_send(dbus_conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

int
init_dbus()
{
	DBusError error;
	int flag;
	dbus_error_init(&error);

	dbus_conn = dbus_bus_get_private(DBUS_BUS_SESSION,&error);

	if(dbus_error_is_set(&error)) 
	{
		fprintf(stderr,"Error- could not initizalize dbus session: %s \n", error.message);
		return -1;
	}

	switch(flag = dbus_bus_request_name(dbus_conn, DBUS_NAME, DBUS_NAME_FLAG_DO_NOT_QUEUE, &error))
	{
		case DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER:
		case DBUS_REQUEST_NAME_REPLY_IN_QUEUE:
			//printf("serwer.c request_name flags %d\n",flag);
			//printf("serwer.c Name registered as %s\n",DBUS_NAME);
			break;
		default:
			printf("serwer.c Error - could not request name\n");
			return -1;
	}

	dbus_vtable = malloc(sizeof(DBusObjectPathVTable));
	dbus_vtable->unregister_function = NULL;

	dbus_vtable->message_function = handler_function;

	if(!dbus_connection_register_object_path(dbus_conn,
						DBUS_PATH,
						dbus_vtable,
						NULL)) 
	{
		printf("Error - could not register object path");
		return -1;
	}
	
	return 0;

}

void
shutdown_dbus ()
{
	if (dbus_conn) {
		dbus_connection_close(dbus_conn);
		free(dbus_vtable);
	}
}


int 
main(int argc, char **argv)
{
	
	if (init_dbus() < 0) {
		fprintf(stderr, "serwer.c Error initializing dbus\n");
	}
	fprintf(stderr,"Waiting for clients\n");

	while (dbus_connection_read_write(dbus_conn, -1)) {
		while (dbus_connection_dispatch( dbus_conn) != DBUS_DISPATCH_COMPLETE){ 
		}
	}

	shutdown_dbus();
	return 0;
}

