# pam-pico ReadMe

The Pico project is liberating humanity from passwords. See https://www.mypico.org

pam-pico offers a pam module for authentication.

## Documentation

For more details on the pam_pico API, how to build the packages and so on, see:

https://docs.mypico.org/developer/pam_pico/

## Install

If you have autoconf you should be able to install using the following 3 
commands:

```
./configure
make
make install
```

However, we recommend you build the deb or rpm package instead. See the developer docs for details about how to do this.

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

pam-pico is released under the AGPL licence. Read COPYING for information.

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

