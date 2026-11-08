# anogs Killer — no-jailbreak dylib build
# outputs .theos/obj/anogskiller.dylib

TARGET  := iphone:clang:latest:14.0
ARCHS   := arm64 arm64e
DEBUG   := 0
FINALPACKAGE := 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME := anogskiller

# Tweak.xm + litehook's own sources, compiled directly into this dylib
# (litehook ships no build system of its own — its .c/.m files are meant
#  to be compiled as part of the consuming project).
anogskiller_FILES       := Tweak.xm \
                           $(wildcard $(THEOS_PROJECT_DIR)/vendor/litehook/src/*.c) \
                           $(wildcard $(THEOS_PROJECT_DIR)/vendor/litehook/src/*.m)

anogskiller_CFLAGS      := -fobjc-arc \
                           -fvisibility=hidden \
                           -I$(THEOS_PROJECT_DIR)/vendor/litehook/include

anogskiller_LDFLAGS     := -Wl,-undefined,dynamic_lookup \
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
