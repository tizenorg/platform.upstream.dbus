#!/bin/sh

CONF_DIR_PATH="/etc/dbus-1/conf_dbus"

echo "copying legacy dbus modified service files..."
rm /usr/lib/systemd/system/graphical.target.wants/xorg.target 2>/dev/null
rm -rf /usr/lib/systemd/system/xorg* 2>/dev/null
rm /usr/lib/systemd/user/tizen-middleware.target.wants/dbus.service 2>/dev/null
ln -s /usr/lib/systemd/user/xorg.service /usr/lib/systemd/user/xorg.target.wants/
ln -s /usr/lib/systemd/user/xorg_done.service /usr/lib/systemd/user/xorg.target.wants/
cp -a $CONF_DIR_PATH/* /
if [ "$?" -ne 0 ]; then
	echo "error occured on copying!"
else
	echo "syncing..."
	sync
	echo "now reset and flash the kernel not using kdbus"
fi
