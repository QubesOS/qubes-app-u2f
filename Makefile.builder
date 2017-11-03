ifneq ($(PACKAGE_SET),dom0)
RPM_SPEC_FILES := rpm_spec/qubes-u2f.spec
DEBIAN_BUILD_DIRS := debian
else
RPM_SPEC_FILES := rpm_spec/qubes-u2f-dom0.spec
endif

# vim: ft=make
