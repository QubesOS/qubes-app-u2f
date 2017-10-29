PYTHON ?= python3
UNITDIR ?= /usr/lib/systemd/system
MANDIR ?= /usr/share/man
QREXECDIR ?= /etc/qubes-rpc

.PHONY: all
all:
	$(PYTHON) setup.py build

.PHONY: install
install:
	$(PYTHON) setup.py install -O1 --skip-build --root $(DESTDIR) \
		$(SETUPOPTS)
	install -d $(DESTDIR)$(UNITDIR)
	install -t $(DESTDIR)$(UNITDIR) systemd/*
	install -d $(DESTDIR)$(QREXECDIR)
	install -t $(DESTDIR)$(QREXECDIR) qubes-rpc/*

.PHONY: install
install-policy:
	install -d $(DESTDIR)$(QREXECDIR)/policy
	install -t $(DESTDIR)$(QREXECDIR)/policy qubes-rpc-policy/*

.PHONY: clean
clean:
	$(RM) -r build dist *.egg-info */__pycache__
