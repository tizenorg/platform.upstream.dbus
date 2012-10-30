#!/bin/bash
# vim:sw=4 et
# This script is called automatically during autobuild checkin.

cp -lf dbus.changes dbus-x11.changes

for spec in dbus-x11.spec; do
    cp -f $spec.in $spec
    for n in $(seq 1 10); do
        grep -q "COMMON$n-BEGIN" dbus.spec || continue
        { sed -n -e "1,/COMMON$n-BEGIN/p" $spec
          sed -n -e "/COMMON$n-BEGIN/,/COMMON$n-END/p" dbus.spec
          sed -n -e "/COMMON$n-END/,\$p" $spec.in; } > $spec.tmp && mv $spec.tmp $spec
    done

    # assuming hilbert has no such dir 
    #if test -x /mounts/work/src/bin/tools/prepare_spec; then
    #    /mounts/work/src/bin/tools/prepare_spec $spec > $spec.tmp && mv $spec.tmp $spec
    #fi
done

osc service localrun format_spec_file
