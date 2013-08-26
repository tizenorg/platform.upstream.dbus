SERVER_DBUS_SOURCES=serwer.c

CLIENT_DBUS_SOURCES=client.c

SQLITE_CFLAGS=`pkg-config --cflags sqlite3`
SQLITE_LIBS=`pkg-config --libs sqlite3`

DBUS_CFLAGS=`pkg-config --cflags dbus-1`
DBUS_LIBS=`pkg-config --libs dbus-1`

INCLUDES=-Wall -g -O0

all: ping-server ping-client 

ping-server: 
	gcc -o $@ $(SERVER_DBUS_SOURCES) $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS) $(SQLITE_CFLAGS) $(SQLITE_LIBS)

ping-client: 
	gcc -o $@ $(CLIENT_DBUS_SOURCES) $(INCLUDES) $(DBUS_CFLAGS) $(CFLAGS) $(DBUS_LIBS) $(SQLITE_CFLAGS) $(SQLITE_LIBS) 

clean:
	rm -f *.o ping-server ping-client
