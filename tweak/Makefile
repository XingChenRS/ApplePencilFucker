TARGET := iphone:clang:16.5:14.0
# arm64 only: the Linux toolchain emits an arm64e slice whose ABI does not match
# iOS 16 (ld warns "incompatible arm64e ABI compiler"), and loading that slice
# into accessoryd dies with SIGBUS inside the tweak. arm64 slices run fine on
# arm64e hardware.
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PencilGen1Compat
PencilGen1Compat_FILES = Tweak.x
PencilGen1Compat_CFLAGS = -fobjc-arc
# MGGetBoolAnswer lives in a private framework, so leave it to the loader.
PencilGen1Compat_LDFLAGS = -Wl,-undefined,dynamic_lookup

# accessoryd is a long-lived daemon: launchd has to respawn it for the injected
# dylib to load, both for `make install` and for the generated deb postinst.
INSTALL_TARGET_PROCESSES = accessoryd

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 accessoryd || true"
