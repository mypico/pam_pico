AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I build

# Support systemd with make distcheck
# See man 7 daemon ("Installing Systemd Service Files" section) for details
DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

pamdir = $(libdir)/security

bin_PROGRAMS      = pico-pair pico-continuous pico-test
pam_LTLIBRARIES   = pam_pico.la 
noinst_LTLIBRARIES   = lib_pam_test.la lib_service_test.la lib_mockpam.la lib_mockbt.la lib_mockdbus.la

dist_doc_DATA  = AUTHORS ChangeLog INSTALL NEWS README.md

MODULES_LDFLAGS = -avoid-version -module -shared -export-dynamic

CORE_SRC  =
CORE_SRC += src/pam_pico.h

# Generate service gdbus code
gdbus_generated_cont = src/gdbus-generated-cont.c src/gdbus-generated-cont.h

$(gdbus_generated_cont): src/pico-cont-auth-gdbus.xml
	$(AM_V_GEN) \
	$(GDBUS_CODEGEN) --interface-prefix uk.ac.cam.cl.pico.. --generate-c-code src/gdbus-generated-cont --c-namespace Pico --c-generate-object-manager --generate-docbook doc/generated-docs $<

# Generate BLE gdbus code
gdbus_generated_ble = src/gdbus-generated-ble.c src/gdbus-generated-ble.h

$(gdbus_generated_ble): src/pico-ble-gdbus.xml
	$(AM_V_GEN) \
	$(GDBUS_CODEGEN) --interface-prefix org.bluez --generate-c-code src/gdbus-generated-ble --c-generate-object-manager --generate-docbook doc/generated-docs $<



# Pairing executable
pico_pair_SOURCES = \
	src/pico-pair.c \
	$(CORE_SRC)

pico_pair_CFLAGS = -DPICOPAIRDIR=\"$(datadir)/@PACKAGE@\" -DPICOKEYDIR=\"/etc/pam-pico\" $(AM_CFLAGS) @PICO_CFLAGS@ @PICOBT_CFLAGS@ @GLIB_CFLAGS@ @GTK_CFLAGS@ @QRENCODE_CFLAGS@ @URLDISPATCHER_CFLAGS@
pico_pair_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) @PICO_LIBS@ @PICOBT_LIBS@ @GLIB_LIBS@ @GTK_LIBS@ @QRENCODE_LIBS@ @URLDISPATCHER_LIBS@ -lpam

# Service testing executable
pico_test_SOURCES = \
	src/pico-test.c \
	$(CORE_SRC)

pico_test_CFLAGS = $(AM_CFLAGS) @PICO_CFLAGS@ @PICOBT_CFLAGS@ @GLIB_CFLAGS@ @DBUSGLIB_CFLAGS@
pico_test_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) @PICO_LIBS@ @PICOBT_LIBS@ @DBUSGLIB_LIBS@ @GLIB_LIBS@ -lpam

# Continuous authenticaton service
pico_continuous_SOURCES = \
	$(gdbus_generated_cont) \
	$(gdbus_generated_ble) \
	src/pico-continuous.c \
	src/processstore.c \
	src/auththread.c \
	src/beaconthread.c \
	src/beaconsend.c \
	src/authconfig.c \
	src/service.c \
	src/servicebtc.c \
	src/servicervp.c \
	src/serviceble.c \
	src/processstore.h \
	src/auththread.h \
	src/beaconthread.h \
	src/beaconsend.h \
	src/authconfig.h \
	src/service.h \
	src/service_private.h \
	src/servicebtc.h \
	src/servicervp.h \
	src/serviceble.h \
	$(CORE_SRC)

pico_continuous_CFLAGS = $(AM_CFLAGS) @PICO_CFLAGS@ @PICOBT_CFLAGS@ @GLIB_CFLAGS@ @DBUSGLIB_CFLAGS@
pico_continuous_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) @PICO_LIBS@ @PICOBT_LIBS@ @GLIB_LIBS@ @DBUSGLIB_LIBS@

# PAM module
pam_pico_la_SOURCES = \
	$(gdbus_generated_cont) \
	src/pam_pico.c \
	$(CORE_SRC)

pam_pico_la_LIBADD  = -lpam @PICO_LIBS@ @PICOBT_LIBS@ @DBUSGLIB_LIBS@ @GLIB_LIBS@
pam_pico_la_CFLAGS  = -fPIC $(AM_CFLAGS) @PICO_CFLAGS@ @PICOBT_CFLAGS@ @GLIB_CFLAGS@ @DBUSGLIB_CFLAGS@
pam_pico_la_LDFLAGS = -avoid-version -module -Wl,-z,nodelete $(AM_LDFLAGS) $(MODULES_LDFLAGS) -export-symbols-regex "pam_sm_(setcred|open_session|authenticate)"

# Tests
lib_pam_test_la_SOURCES = \
	src/pam_pico.c \
	$(CORE_SRC)

lib_pam_test_la_LIBADD  = @PICO_LIBS@
lib_pam_test_la_CFLAGS  = $(AM_CFLAGS) @PICO_CFLAGS@ @PICOBT_CFLAGS@ @GLIB_CFLAGS@ @DBUSGLIB_CFLAGS@
lib_pam_test_la_LDFLAGS = $(AM_LDFLAGS) 

lib_service_test_la_SOURCES = \
	$(gdbus_generated_cont) \
	src/pico-continuous.c \
	src/processstore.c \
	src/auththread.c \
	src/beaconthread.c \
	src/beaconsend.c \
	src/authconfig.c \
	src/service.c \
	src/servicebtc.c \
	src/servicervp.c \
	src/processstore.h \
	src/auththread.h \
	src/beaconthread.h \
	src/beaconsend.h \
	src/authconfig.h \
	src/service.h \
	src/service_private.h \
	src/servicebtc.h \
	src/servicervp.h \
	$(CORE_SRC)

lib_service_test_la_LIBADD  =  @PICO_LIBS@ @GLIB_LIBS@
lib_service_test_la_CFLAGS = -DBASE_DIR=\"./tests/keydir/\" $(AM_CFLAGS) @PICO_CFLAGS@ @GLIB_CFLAGS@
lib_service_test_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS)

lib_mockpam_la_SOURCES = \
	tests/mockpam/mockpam.c 

lib_mockbt_la_SOURCES = \
	tests/mockbt/mockbt.c 
lib_mockbt_la_CFLAGS  = $(AM_CFLAGS) @PICOBT_CFLAGS@

lib_mockdbus_la_SOURCES = \
	tests/mockdbus/mockdbus.c 
lib_mockdbus_la_CFLAGS  = $(AM_CFLAGS) @DBUSGLIB_CFLAGS@

# Tests
TESTS = tests/test_pam tests/test_auth tests/test_beacons #tests/test_service

check_PROGRAMS = $(TESTS)

tests_test_pam_CFLAGS = $(AM_CFLAGS) @PICO_CFLAGS@ @CHECK_CFLAGS@ @PICOBT_CFLAGS@ @GLIB_CFLAGS@ @DBUSGLIB_CFLAGS@
tests_test_pam_LDADD = .libs/lib_pam_test.la .libs/lib_mockpam.la .libs/lib_mockbt.la .libs/lib_mockdbus.la @CHECK_LIBS@ @PICO_LIBS@

tests_test_auth_CFLAGS = $(AM_CFLAGS) @PICO_CFLAGS@ @CHECK_CFLAGS@ @PICOBT_CFLAGS@ @DBUSGLIB_CFLAGS@ @GLIB_CFLAGS@
tests_test_auth_LDADD = .libs/lib_pam_test.la .libs/lib_mockpam.la .libs/lib_mockbt.la .libs/lib_mockdbus.la @CHECK_LIBS@ @PICO_LIBS@

tests_test_beacons_CFLAGS = $(AM_CFLAGS) @PICO_CFLAGS@ @CHECK_CFLAGS@ @PICOBT_CFLAGS@ @DBUSGLIB_CFLAGS@ @GLIB_CFLAGS@
tests_test_beacons_LDADD = .libs/lib_service_test.la .libs/lib_mockpam.la .libs/lib_mockbt.la .libs/lib_mockdbus.la @CHECK_LIBS@ @PICO_LIBS@

#tests_test_service_CFLAGS = $(AM_CFLAGS) @PICO_CFLAGS@ @CHECK_CFLAGS@ @GLIB_CFLAGS@
#tests_test_service_LDADD = .libs/lib_service_test.la .libs/lib_mockbt.la @CHECK_LIBS@ @PICO_LIBS@ @GLIB_LIBS@


.PHONY: check-valgrind ;
check-valgrind: $(TESTS)
	@cd tests
	@for test in $$(echo $(TESTS) | sed 's/tests\/\([^ ]\)/tests\/.libs\/lt-\1/g') ; do \
		CK_FORK=no $(VALGRIND) --error-exitcode=1 --leak-resolution=low --quiet \
		--leak-check=full --show-possibly-lost=no --suppressions=valgrind.suppressions $${test} ; \
	done


#check_PROGRAMS    = examples/demo tests/pam_google_authenticator_unittest
#check_LTLIBRARIES = libpam_google_authenticator_testing.la
#TESTS             = tests/pam_google_authenticator_unittest

#libpam_google_authenticator_testing_la_SOURCES = \
#	src/pam_google_authenticator.c \
#	$(CORE_SRC)
#libpam_google_authenticator_testing_la_CFLAGS  = $(AM_CFLAGS) -DTESTING=1
#libpam_google_authenticator_testing_la_LDFLAGS = $(AM_LDFLAGS) $(MODULES_LDFLAGS) -rpath $(abs_top_builddir)

#tests_pam_google_authenticator_unittest_SOURCES = \
#	tests/pam_google_authenticator_unittest.c \
#	$(CORE_SRC)
#tests_pam_google_authenticator_unittest_LDFLAGS = $(AM_LDFLAGS) -export-dynamic

#test: check


#examples_demo_SOURCES = \
#	src/pam_google_authenticator.c \
#	$(CORE_SRC) \
#	examples/demo.c
#examples_demo_CFLAGS = $(AM_CFLAGS) -DDEMO=1

SUBDIRS = doc service assets

# /etc/pam.d/pico-pair config file added to debian/libpam-pico.install
# so it won't get installed with make install, unfortunately (but will be
# installed by the deb package).
#install-data-local: etc/pam.d/pico-pair
#	$(INSTALL_DATA) etc/pam.d/pico-pair /etc/pam.d/pico-pair

super-clean: maintainer-clean
	rm -fr aclocal autom4te.cache/ m4 missing libtool config.guess
	rm -fr config.lt config.status config.sub configure depcomp
	rm -fr libtool install-sh  *~ Makefile aclocal.m4 config.h.in ltmain.sh
	rm -fr Makefile.in test-driver compile

export VERSION

.PHONY: doxygen

doxygen:
	$(DOXYGEN) doxyfile
#	@if test "$DOXYGEN" = doxygen; then \
#		$(DOXYGEN) doxyfile; \
#	else \
#		echo "Please install doxygen to generate the documentation."; \
#	fi

