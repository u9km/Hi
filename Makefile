# anogs Killer — no-jailbreak dylib build
# outputs .theos/obj/anogskiller.dylib

TARGET  := iphone:clang:latest:14.0
ARCHS   := arm64 arm64e
DEBUG   := 0
FINALPACKAGE := 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME := anogskiller

anogskiller_FILES       := Tweak.xm
anogskiller_CFLAGS      := -fobjc-arc \
                           -fvisibility=hidden \
                           -I$(THEOS_PROJECT_DIR)/vendor/litehook/include
anogskiller_LDFLAGS     := -L$(THEOS_PROJECT_DIR)/vendor/litehook/lib \
                           -llitehook \
                           -Wl,-undefined,dynamic_lookup \
                           -Wl,-dead_strip
anogskiller_FRAMEWORKS  := Foundation UIKit

# no install to any prefix — dylib only
anogskiller_INSTALL_PATH := /usr/lib

include $(THEOS_MAKE_PATH)/library.mk

# ---------- convenience targets ----------
.PHONY: dylib clean-all

dylib: all
	@echo "== dylib produced =="
	@find .theos/obj -name "*.dylib" -exec ls -lh {} \; \
	  -exec file {} \; \
	  -exec lipo -info {} \;

clean-all: clean
	@rm -rf .theos packages vendor/litehook
