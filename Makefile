PYTHON ?= python3
UNITDIR ?= /usr/lib/systemd/system
PRESETDIR ?= /usr/lib/systemd/system-preset
MANDIR ?= /usr/share/man
QREXECDIR ?= /etc/qubes-rpc
UDEVRULESDIR ?= /lib/udev/rules.d

.PHONY: all
all:
	$(PYTHON) setup.py build

.PHONY: install
install:
	$(PYTHON) setup.py install -O1 --skip-build --root $(DESTDIR) \
		$(SETUPOPTS)
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 -t $(DESTDIR)$(UNITDIR) systemd/*.service
	install -d $(DESTDIR)$(PRESETDIR)
	install -m 0644 -t $(DESTDIR)$(PRESETDIR) systemd/*.preset
	install -d $(DESTDIR)$(QREXECDIR)
	install -t $(DESTDIR)$(QREXECDIR) qubes-rpc/*
	install -d $(DESTDIR)$(UDEVRULESDIR)
	install -m 0644 -t $(DESTDIR)$(UDEVRULESDIR) udev/*

.PHONY: install
install-policy:
	install -d $(DESTDIR)$(QREXECDIR)/policy
	install -m 0664 -t $(DESTDIR)$(QREXECDIR)/policy qubes-rpc-policy/*

.PHONY: clean
clean:
	$(RM) -r build dist *.egg-info */__pycache__
