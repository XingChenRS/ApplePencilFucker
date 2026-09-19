TARGET := iphone:clang:16.5:14.0
ARCHS = arm64e arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = PencilGen1Compat
PencilGen1Compat_FILES = Tweak.x
PencilGen1Compat_CFLAGS = -fobjc-arc

# accessoryd is a long-lived daemon: launchd has to respawn it for the injected
# dylib to load, both for `make install` and for the generated deb postinst.
INSTALL_TARGET_PROCESSES = accessoryd

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 accessoryd || true"
