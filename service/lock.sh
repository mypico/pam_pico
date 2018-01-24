#!/bin/sh
# Script for locking the user's session
# The correct user should be passed as a parameter
# Tested with unity

user=$1

if [ "$user" != "" ]; then
	#aplay -q /usr/share/pico/button-11.wav
	#xdotool key super+l

	PID_CHECK=$(pidof -s compiz)
	PID_DBUS=$(pidof -s gnome-screensaver)
	if [ $PID_CHECK ]; then
		echo "User = $user"

		QUERY_ENVIRON="$(tr '\0' '\n' < /proc/${PID_CHECK}/environ | grep "DBUS_SESSION_BUS_ADDRESS" | cut -d "=" -f 2-)"
		if [ "${QUERY_ENVIRON}" != "" ]; then
			export DBUS_SESSION_BUS_ADDRESS="${QUERY_ENVIRON}"
			echo "Connected to session:"
			echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS}"
		else
			echo "Could not find dbus session ID in user environment."
			return 1
		fi

		echo $DBUS_SESSION_BUS_ADDRESS
		#su $user -c "gnome-screensaver-command --lock"
		su $user -c "dbus-send --type=method_call --dest=org.gnome.ScreenSaver /org/gnome/ScreenSaver org.gnome.ScreenSaver.Lock"
	fi
fi

