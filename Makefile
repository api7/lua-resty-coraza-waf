OUTPUT_NAME ?= coraza_waf.so
GO ?= go
# memoize_builders: compile each regex and pm dictionary once per process and
# share them between rule sets. re2_cgo: use RE2 through cgo for @rx.
GO_TAGS ?= memoize_builders,coraza.rule.multiphase_evaluation,re2_cgo

# RE2_STATIC: prefix written by scripts/build-re2.sh. When set, RE2, Abseil
# and the C++ runtime are linked statically and the library only needs glibc.
# Otherwise the system libre2 found by pkg-config is linked dynamically.
RE2_STATIC ?=
ifneq ($(RE2_STATIC),)
export PKG_CONFIG_PATH := $(RE2_STATIC)/lib/pkgconfig/static
export CGO_LDFLAGS := -static-libstdc++ -static-libgcc -Wl,--exclude-libs,ALL
endif

# Installation, by luarocks (LIBDIR, LUADIR) or by hand (INST_*).
INST_PREFIX ?= /usr/local
INST_LIBDIR ?= $(INST_PREFIX)/lib/lua/5.1
INST_LUADIR ?= $(INST_PREFIX)/share/lua/5.1
LIBDIR ?= $(INST_LIBDIR)
LUADIR ?= $(INST_LUADIR)
INSTALL ?= install

# A release tarball carries prebuilt/coraza_waf-<arch>.so; a git checkout
# does not and builds from source.
ARCH := $(shell uname -m | sed -e 's/^arm64$$/aarch64/' -e 's/^amd64$$/x86_64/')
PREBUILT := prebuilt/coraza_waf-$(ARCH).so

.PHONY: all build test install clean

all:
ifeq ($(wildcard prebuilt),)
	$(MAKE) build
else ifeq ($(wildcard $(PREBUILT)),)
	@echo "no prebuilt library for $(ARCH) in this release;" \
	      "build from a git checkout with Go and libre2-dev instead" >&2
	@exit 1
endif

build:
	cd go && CGO_ENABLED=1 $(GO) build -trimpath -buildvcs=false -buildmode=c-shared \
		-tags $(GO_TAGS) -o $(abspath $(OUTPUT_NAME)) .
	rm -f $(basename $(OUTPUT_NAME)).h

test:
	cd go && CGO_ENABLED=1 $(GO) test -count=1 -tags $(GO_TAGS) ./...

install:
	$(INSTALL) -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(LUADIR)/resty
	$(INSTALL) -m 644 lib/resty/coraza.lua $(DESTDIR)$(LUADIR)/resty/
ifeq ($(wildcard prebuilt),)
	$(INSTALL) -m 755 $(OUTPUT_NAME) $(DESTDIR)$(LIBDIR)/coraza_waf.so
else
	$(INSTALL) -m 755 $(PREBUILT) $(DESTDIR)$(LIBDIR)/coraza_waf.so
endif

clean:
	rm -rf $(OUTPUT_NAME) $(basename $(OUTPUT_NAME)).h build dist
