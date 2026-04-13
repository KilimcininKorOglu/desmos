-- Desmos bonding VPN — LuCI controller.
--
-- Registers the Desmos configuration page under
-- Administration → Services → Desmos VPN.

module("luci.controller.desmos", package.seeall)

function index()
    -- Main entry point: Services → Desmos VPN.
    entry({"admin", "services", "desmos"},
          cbi("desmos"),
          _("Desmos VPN"),
          60)

    -- Status sub-page.
    entry({"admin", "services", "desmos", "status"},
          template("desmos/status"),
          _("Status"),
          10)
end
