configdir=$(sysconfdir)/dbus-1

DBUS_BUS_LIBS = \
        $(XML_LIBS) \
        $(SELINUX_LIBS) \
        $(THREAD_LIBS) \
        $(ADT_LIBS) \
        $(NETWORK_libs) \
        $(LIBSMACK_LIBS) \
        $(NULL)

AM_CPPFLAGS = \
        -I$(top_srcdir) \
        $(XML_CFLAGS) \
        -DDBUS_SYSTEM_CONFIG_FILE=\""$(configdir)/system.conf"\" \
        -DDBUS_COMPILATION \
        -DDBUS_STATIC_BUILD \
        $(LIBSMACK_CFLAGS) \
        $(NULL)

# if assertions are enabled, improve backtraces
AM_LDFLAGS = @R_DYNAMIC_LDFLAG@

dbusincludedir=$(includedir)/dbus-1.0/dbus
dbusarchincludedir=$(libdir)/dbus-1.0/include/dbus

intllibs = @LTLIBINTL@

lib_LTLIBRARIES=libdbuspolicy-1.la

dbusinclude_HEADERS=                            \
        dbus-policy.h

libdbuspolicy_1_la_SOURCES=                     \
        ../bus/activation.c                     \
        ../bus/activation.h                     \
        ../bus/activation-exit-codes.h          \
        ../bus/bus.c                            \
        ../bus/bus.h                            \
        ../bus/config-parser.c                  \
        ../bus/config-parser.h                  \
        ../bus/config-parser-common.c           \
        ../bus/config-parser-common.h           \
        ../bus/connection.c                     \
        ../bus/connection.h                     \
        ../bus/desktop-file.c                   \
        ../bus/desktop-file.h                   \
        ../bus/dir-watch-default.c              \
        ../bus/dir-watch.h                      \
        ../bus/dispatch.c                       \
        ../bus/dispatch.h                       \
        ../bus/driver.c                         \
        ../bus/driver.h                         \
        ../bus/expirelist.c                     \
        ../bus/expirelist.h                     \
        ../bus/policy.c                         \
        ../bus/policy.h                         \
        ../bus/selinux.h                        \
        ../bus/selinux.c                        \
        ../bus/smack.h                          \
        ../bus/smack.c                          \
        ../bus/services.c                       \
        ../bus/services.h                       \
        ../bus/signals.c                        \
        ../bus/signals.h                        \
        ../bus/stats.c                          \
        ../bus/stats.h                          \
        ../bus/test.c                           \
        ../bus/test.h                           \
        ../bus/utils.c                          \
        ../bus/utils.h                          \
        ../bus/config-loader-expat.c            \
        dbus-policy.c                           \
        dbus-policy.h

libdbuspolicy_1_la_CPPFLAGS = \
        $(AM_CPPFLAGS) \
        -Ddbus_1_EXPORTS \
        $(NULL)

libdbuspolicy_1_la_LIBADD= \
        $(top_builddir)/dbus/libdbus-internal.la \
        $(DBUS_BUS_LIBS)

libdbuspolicy_1_la_LDFLAGS = \
        $(AM_LDFLAGS) \
        $(export_symbols) \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -no-undefined \
        $(NULL)

## mop up the gcov files
clean-local:
	/bin/rm *.bb *.bbg *.da *.gcov || true


