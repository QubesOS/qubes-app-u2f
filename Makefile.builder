ifneq ($(PACKAGE_SET),dom0)
ifeq ($(filter $(DIST), centos7 centos8 centos-stream8),)
RPM_SPEC_FILES := rpm_spec/qubes-ctap.spec
endif
ifeq ($(filter $(DIST),jessie buster bullseye),)
DEBIAN_BUILD_DIRS := debian
endif
else
RPM_SPEC_FILES := rpm_spec/qubes-ctap-dom0.spec
endif

# vim: ft=make
