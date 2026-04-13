# OpenWrt package Makefile for Desmos bonding VPN.
#
# Drop this file (or symlink it) into the OpenWrt SDK tree at
#   package/desmos/Makefile
# then run:
#   make package/desmos/compile V=sc
#
# The build shells out to `cargo build --release --target $(RUST_TARGET)`
# inside the SDK environment.  The Rust toolchain (including the
# appropriate cross-compile target) must be pre-installed — the CI
# workflow handles this automatically.
#
# Produces a standard IPK that installs the desmos binary into
# /usr/bin/desmos, a procd init script with UCI→TOML bridge into
# /etc/init.d/desmos, UCI defaults into /etc/config/desmos, and
# LuCI controller/model/view for web-based configuration.

include $(TOPDIR)/rules.mk

PKG_NAME:=desmos
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=KilimcininKorOglu <KilimcininKorOglu>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

# ---- Package metadata -------------------------------------------------------

define Package/desmos
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Desmos connection bonding VPN
  URL:=https://github.com/KilimcininKorOglu/desmos
  DEPENDS:=+kmod-tun +luci-base
  PKGARCH:=$(ARCH)
endef

define Package/desmos/description
  Desmos is a high-performance connection bonding VPN that aggregates
  multiple network links (4G, Wi-Fi, Ethernet, Starlink) into a single
  encrypted tunnel.  Supports round-robin, weighted, latency-adaptive,
  and redundant bonding strategies with sub-second failover.
endef

# ---- Rust target mapping -----------------------------------------------------
#
# Map OpenWrt $(ARCH) to Rust target triples.  The build script
# also accepts RUST_TARGET directly for custom overrides.

ifeq ($(ARCH),mips_24kc)
  RUST_TARGET:=mips-unknown-linux-musl
endif
ifeq ($(ARCH),mipsel_24kc)
  RUST_TARGET:=mipsel-unknown-linux-musl
endif
ifeq ($(ARCH),arm_cortex-a7_neon-vfpv4)
  RUST_TARGET:=armv7-unknown-linux-musleabihf
endif
ifeq ($(ARCH),arm_cortex-a7)
  RUST_TARGET:=armv7-unknown-linux-musleabihf
endif
ifeq ($(ARCH),arm_cortex-a9)
  RUST_TARGET:=armv7-unknown-linux-musleabihf
endif
ifeq ($(ARCH),aarch64_cortex-a53)
  RUST_TARGET:=aarch64-unknown-linux-musl
endif
ifeq ($(ARCH),aarch64_generic)
  RUST_TARGET:=aarch64-unknown-linux-musl
endif
ifeq ($(ARCH),x86_64)
  RUST_TARGET:=x86_64-unknown-linux-musl
endif

# Fallback: allow explicit override via environment.
RUST_TARGET?=x86_64-unknown-linux-musl

# ---- Build -------------------------------------------------------------------

define Build/Compile
	cd $(PKG_BUILD_DIR) && \
	CARGO_TARGET_DIR=$(PKG_BUILD_DIR)/target \
	RUSTFLAGS="-C target-feature=+crt-static" \
	cargo build \
		--release \
		--target $(RUST_TARGET) \
		--manifest-path $(PKG_BUILD_DIR)/Cargo.toml
endef

# ---- Install -----------------------------------------------------------------

define Package/desmos/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) \
		$(PKG_BUILD_DIR)/target/$(RUST_TARGET)/release/desmos \
		$(1)/usr/bin/desmos

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/desmos.init $(1)/etc/init.d/desmos

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/desmos.uci $(1)/etc/config/desmos

	# LuCI controller.
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luci/luasrc/controller/desmos.lua \
		$(1)/usr/lib/lua/luci/controller/desmos.lua

	# LuCI CBI model.
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./luci/luasrc/model/cbi/desmos.lua \
		$(1)/usr/lib/lua/luci/model/cbi/desmos.lua

	# LuCI views.
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/desmos
	$(INSTALL_DATA) ./luci/luasrc/view/desmos/status.htm \
		$(1)/usr/lib/lua/luci/view/desmos/status.htm
endef

$(eval $(call BuildPackage,desmos))
