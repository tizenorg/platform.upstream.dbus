#include <stdio.h>

#include <dbus/dbus.h>

#include <string.h>
#include <sys/time.h>
#include <stdlib.h>

#define DBUS_NAME "com.samsung.pingpong"
#define DBUS_PATH "/com/samsung/pingpong"
#define DBUS_IFACE "com.samsung.pingpong"

DBusConnection *dbus_conn;
struct timeval tv_start, tv_end;
unsigned int message_serial;
long int iterations = 0;
long int avg = 0;
long int sum = 0;
static char* ping = "pingping";
int MSG_SIZE  = 1024*1024;
//#define MSG_SIZE 3 * 1024 * 1024

void
shutdown_dbus ()
{
	if (dbus_conn) {
		dbus_connection_close (dbus_conn);
	}
}

DBusHandlerResult handler(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	//char buffer[1024];
	DBusError error;
	const char *dbus_data;
	long int delta = 0;
	DBusMessage *message;
	
	if (dbus_message_get_reply_serial (msg) != message_serial) {
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_error_init (&error);
	if(!dbus_message_get_args (msg,&error,DBUS_TYPE_STRING,&dbus_data,DBUS_TYPE_INVALID)) 	{
		fprintf (stderr,"error: %s\n",error.message);
		return -1;
	} else {
		if(dbus_data[5] != 'v') {
		  fprintf (stderr,"error: string content not right! \n");
		  return -1;
		}
		  
		gettimeofday (&tv_end, NULL);
 		delta = (1000000*tv_end.tv_sec + tv_end.tv_usec) - (1000000*tv_start.tv_sec + tv_start.tv_usec);
		//printf ("delta: %ld us\n", delta);	
		sum += delta;
		iterations++;
		//if(iterations == 10) {
			avg = sum / iterations;
			printf ("avg RTT: %ld us\n", avg);
			shutdown_dbus ();
		//}
		gettimeofday (&tv_start, NULL);
		message = dbus_message_new_method_call (DBUS_NAME, DBUS_PATH, DBUS_IFACE, "PING");
		dbus_message_append_args (message, DBUS_TYPE_STRING, &ping, DBUS_TYPE_INVALID);
		dbus_connection_send (dbus_conn, message, &message_serial);
		dbus_message_unref (message);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

int
init_dbus ()
{
	DBusError error;
	dbus_error_init (&error);
	
	dbus_conn = dbus_bus_get_private(DBUS_BUS_SESSION, &error);

	if (dbus_error_is_set (&error)) {
		fprintf (stderr, "Couldn't initialize DBus: %s\n", error.message);

		return -1;
	}

	return 0;
}

int
main (int argc, char **argv)
{
	
	DBusMessage *message;
	int i;
	
	if (argc > 1)
		MSG_SIZE = atoi(argv[1]);
	
	if (init_dbus () < 0) {
		fprintf (stderr, "Cannot initialize DBus\n");
		return 1;
	}

	dbus_connection_add_filter (dbus_conn, handler, NULL, NULL);

	ping = malloc(MSG_SIZE);
	for(i = 0; i < MSG_SIZE; i++) ping[i] = 'v';
	ping[MSG_SIZE-1] = '\0';
	//printf("MSG_SIZE: %i\n", MSG_SIZE);
	
	message = dbus_message_new_method_call (DBUS_NAME, DBUS_PATH, DBUS_IFACE, "PING");
	dbus_message_append_args (message, DBUS_TYPE_STRING, &ping, DBUS_TYPE_INVALID);
	dbus_connection_send (dbus_conn, message, &message_serial);

	gettimeofday (&tv_start, NULL);

	dbus_message_unref (message);
	while (dbus_connection_read_write (dbus_conn, -1)) {
		while (dbus_connection_dispatch (dbus_conn) != DBUS_DISPATCH_COMPLETE) {
		}
	}
	free(ping);

	return 0;
}
