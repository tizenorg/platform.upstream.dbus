#!/bin/sh

CONF_DIR_PATH="/etc/dbus-1/conf_kdbus"

echo "copying kdbus-modified service files..."
rm /usr/lib/systemd/user/xorg.target.wants/* 2>/dev/null
cp -a $CONF_DIR_PATH/* /
if [ "$?" -ne 0 ]; then
	echo "error occured on copying!"
else
	echo "syncing..."
	sync
	echo "now reset and flash the kernel using kdbus"
fi
