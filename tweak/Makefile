TARGET := iphone:clang:16.5:14.0
ARCHS = arm64 arm64e
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

# The Linux linker labels its arm64e output with the pre-iOS-14 ABI, which iOS 16
# daemons cannot run: the tweak loads, then the host SIGBUSes on the first
# authenticated pointer. Mark the slice as ABI v2 and re-sign, because patching
# rewrites bytes inside the signed range.
after-stage::
	@for lib in $$(find "$(THEOS_STAGING_DIR)" -name '$(TWEAK_NAME).dylib'); do \
		python3 "$(THEOS_PROJECT_DIR)/tools/fix_arm64e_abi.py" "$$lib"; \
		"$(TARGET_CODESIGN)" $(TARGET_CODESIGN_FLAGS) "$$lib" && echo "  re-signed: $$lib"; \
	done

after-install::
	install.exec "killall -9 accessoryd || true"
