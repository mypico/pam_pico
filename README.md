# pam_pico ReadMe

The Pico project is liberating humanity from passwords. See https://www.mypico.org

pam_pico offers a pam module for authentication.

## Documentation

For more details on the pam_pico code and how to build the entire Pico stack, see the developer docs.

https://docs.mypico.org/developer/

If you want to build all the Pico components from source in one go, without having to worry about the details, see:

https://github.com/mypico/pico-build-all

## Install from source

You'll need to ensure you've installed the [build dependencies](https://docs.mypico.org/developer/pam_pico/#deps) before you attempt to compile and install pam_pico. This includes building and installing libpicobt and libpico from the Pico repositories. See the [libpicobt](https://github.com/mypico/libpicobt) and the [libpico](https://github.com/mypico/libpico) repositories for instructions for this.

If you're using Ubuntu 16.04, you can install the remaining build dependencies using `apt`.

```
sudo apt install autoconf autotools-dev libcurl4-openssl-dev libqrencode-dev check cmake \
  libpam0g-dev gcovr libbluetooth-dev libsoup2.4-dev devscripts openssh-client git debhelper \
  libtool pkg-config libssl-dev libglib2.0-dev dh-systemd libdbus-glib-1-dev libgtk-3-dev \
  liburl-dispatcher1-dev doxygen graphviz
```

Assuming you've got all these, download the latest version from the git repository and move inside the project folder.

```
git clone git@github.com:mypico/pam_pico.git
cd pam_pico
```

You can now build using autoconf with the following commands:

```
./configure
make
```

After this, the cleanest way to install it is to build the deb or rpm package and install that:

```
debuild -us -uc -b --lintian-opts -X changes-file
sudo dpkg -i ../libpam-pico_0.0.2-1_amd64.deb
```

## Continuous Authentication Service

The package installs the pico-continuous service to support continuous 
authentication. Systemd support is included for managiing the service. The
following commnds can be used.

Check status:
```
systemctl status pico-continuous.service
sudo journalctl -u pico-continous
gdbus introspect --system --dest uk.ac.cam.cl.pico.service --object-path /PicoObject
```

Start, stop, reload, enable, disable:
```
systemctl start pico-continuous.service
systemctl stop pico-continuous.service
systemctl daemon-reload
systemctl enable pico-continuous.service
systemctl disable pico-continuous.service
```

The systemd unit configuration can be found at:
```
/lib/systemd/system/pico-continuous.service
```

The dbus policy that allows the service to use the system bus can be found at:
```
/etc/dbus-1/system.d/uk.ac.cam.cl.pico.service.conf
```

## License

pam_pico is released under the AGPL licence. Read COPYING for information.

## Contributing

We welcome comments and contributions to the project. If you're interested in contributing please see here: https://get.mypico.org/cla/

Contact and Links
=================

More information can be found at: http://mypico.org

The Pico project team:
 * Frank Stajano (PI), Frank.Stajano@cl.cam.ac.uk
 * David Llewellyn-Jones, David.Llewellyn-Jones@cl.cam.ac.uk
 * Claudio Dettoni, cd611@cam.ac.uk
 * Seb Aebischer, seb.aebischer@cl.cam.ac.uk
 * Kat Krol, kat.krol@cl.cam.ac.uk
 * David Harrison, David.Harrison@cl.cam.ac.uk

