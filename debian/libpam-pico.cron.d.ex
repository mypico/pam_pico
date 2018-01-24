#
# Regular cron jobs for the libpam-pico package
#
0 4	* * *	root	[ -x /usr/bin/libpam-pico_maintenance ] && /usr/bin/libpam-pico_maintenance
