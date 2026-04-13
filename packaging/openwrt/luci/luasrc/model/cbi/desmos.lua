-- Desmos bonding VPN — LuCI CBI model.
--
-- Maps UCI /etc/config/desmos sections to form fields.
-- Saving the form writes back to UCI; the init script
-- converts UCI → TOML on the next service restart.

local m, s, o

m = Map("desmos", translate("Desmos Bonding VPN"),
    translate("Configure the Desmos connection bonding VPN."))

-- ---- General ----------------------------------------------------------------

s = m:section(NamedSection, "main", "desmos",
    translate("General Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable"))
o.rmempty = false

o = s:option(ListValue, "mode", translate("Mode"))
o:value("client", translate("Client"))
o:value("server", translate("Server"))
o.default = "client"

o = s:option(ListValue, "log_level", translate("Log Level"))
o:value("error",   translate("Error"))
o:value("warn",    translate("Warning"))
o:value("info",    translate("Info"))
o:value("debug",   translate("Debug"))
o.default = "info"

o = s:option(Flag, "verbose", translate("Verbose Output"))
o.rmempty = false

-- ---- Server -----------------------------------------------------------------

s = m:section(NamedSection, "server", "server",
    translate("Server Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "listen_addr", translate("Listen Address"))
o.default = "0.0.0.0"
o.datatype = "ipaddr"
o:depends("main.mode", "server")

o = s:option(Value, "listen_port", translate("Listen Port"))
o.default = "51820"
o.datatype = "port"
o:depends("main.mode", "server")

o = s:option(Value, "max_clients", translate("Max Clients"))
o.default = "100"
o.datatype = "uinteger"
o:depends("main.mode", "server")

-- ---- Client -----------------------------------------------------------------

s = m:section(NamedSection, "client", "client",
    translate("Client Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "server_addr", translate("Server Address"))
o.datatype = "host"
o:depends("main.mode", "client")

o = s:option(Value, "server_port", translate("Server Port"))
o.default = "51820"
o.datatype = "port"
o:depends("main.mode", "client")

o = s:option(Value, "psk", translate("Pre-Shared Key"))
o.password = true
o:depends("main.mode", "client")

-- ---- TUN Interface ----------------------------------------------------------

s = m:section(NamedSection, "tun", "interface",
    translate("TUN Interface"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "name", translate("Interface Name"))
o.default = "desmos0"

o = s:option(Value, "mtu", translate("MTU"))
o.default = "1420"
o.datatype = "range(576, 9000)"

-- ---- P2P --------------------------------------------------------------------

s = m:section(NamedSection, "p2p", "p2p",
    translate("Peer-to-Peer"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enabled", translate("Enable P2P"))
o.rmempty = false

o = s:option(Value, "stun_server", translate("STUN Server"))
o.default = "stun.l.google.com:19302"

-- ---- Bonding ----------------------------------------------------------------

s = m:section(NamedSection, "bonding", "bonding",
    translate("Bonding"))
s.anonymous = true
s.addremove = false

o = s:option(ListValue, "strategy", translate("Strategy"))
o:value("round_robin",       translate("Round Robin"))
o:value("weighted",          translate("Weighted"))
o:value("latency_adaptive",  translate("Latency Adaptive"))
o:value("redundant",         translate("Redundant"))
o.default = "latency_adaptive"

o = s:option(Value, "failover_threshold", translate("Failover Threshold (%)"))
o.default = "20"
o.datatype = "range(1, 100)"

-- ---- Bond Interfaces (repeatable) -------------------------------------------

s = m:section(TypedSection, "bond_interface",
    translate("Bonded Interfaces"),
    translate("Network interfaces to aggregate. Add one entry per link."))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Value, "name", translate("Interface"))
o.datatype = "network"
o.rmempty = false

o = s:option(Value, "weight", translate("Weight"))
o.default = "100"
o.datatype = "range(1, 10000)"

return m
