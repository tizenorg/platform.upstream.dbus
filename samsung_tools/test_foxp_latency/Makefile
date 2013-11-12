default:   ping-client ping-server

ping-client:
	$(CC) -o ping-client ping-client.c -Wall -g -O0 `pkg-config --cflags --libs dbus-1` 
	
ping-server:
	$(CC) -o ping-server ping-server.c -Wall -g -O0 `pkg-config --cflags --libs dbus-1` 

install:
	

clean:
	-rm -f ping-client ping-server *~
