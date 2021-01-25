ifneq ($(PACKAGE_SET),dom0)
ifneq ($(DISTRIBUTION),centos)
RPM_SPEC_FILES := rpm_spec/qubes-u2f.spec
endif
ifneq ($(DIST),jessie)
DEBIAN_BUILD_DIRS := debian
endif
else
RPM_SPEC_FILES := rpm_spec/qubes-u2f-dom0.spec
endif

# vim: ft=make
