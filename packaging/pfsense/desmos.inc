<?php
/*
 * desmos.inc — pfSense package PHP include.
 *
 * Handles config save/load, TOML generation from pfSense XML
 * config, and service start/stop/restart hooks.
 *
 * Called by the pfSense package framework via the custom_php_*
 * commands defined in desmos.xml.
 */

require_once("config.inc");
require_once("service-utils.inc");
require_once("util.inc");

define('DESMOS_CONF_DIR', '/usr/local/etc/desmos');
define('DESMOS_CONF_FILE', '/usr/local/etc/desmos/desmos.toml');
define('DESMOS_RC_SCRIPT', '/usr/local/etc/rc.d/desmos.sh');
define('DESMOS_BIN', '/usr/local/bin/desmos');

/**
 * Called on package install.
 */
function desmos_install() {
    safe_mkdir(DESMOS_CONF_DIR);
    desmos_write_rcscript();
    desmos_resync();
}

/**
 * Called on package removal.
 */
function desmos_deinstall() {
    desmos_stop();
    @unlink(DESMOS_CONF_FILE);
    @unlink(DESMOS_RC_SCRIPT);
    @rmdir(DESMOS_CONF_DIR);
}

/**
 * Called on config save — regenerate TOML and restart if enabled.
 */
function desmos_resync() {
    $cfg = desmos_get_config();
    desmos_write_toml($cfg);

    if (isset($cfg['enable']) && $cfg['enable'] === 'on') {
        desmos_restart();
    } else {
        desmos_stop();
    }
}

/**
 * Read the desmos config from pfSense XML.
 */
function desmos_get_config() {
    global $config;
    if (isset($config['installedpackages']['desmos']['config'][0])) {
        return $config['installedpackages']['desmos']['config'][0];
    }
    return array();
}

/**
 * Convert pfSense XML config to desmos TOML.
 */
function desmos_write_toml($cfg) {
    safe_mkdir(DESMOS_CONF_DIR);

    $mode = isset($cfg['mode']) ? $cfg['mode'] : 'client';
    $log_level = isset($cfg['log_level']) ? $cfg['log_level'] : 'info';

    $toml = "[general]\n";
    $toml .= "mode = \"{$mode}\"\n";
    $toml .= "log_level = \"{$log_level}\"\n";

    // Server section.
    if ($mode === 'server') {
        $listen_addr = isset($cfg['listen_addr']) ? $cfg['listen_addr'] : '0.0.0.0';
        $server_port = isset($cfg['server_port']) ? $cfg['server_port'] : '51820';
        $max_clients = isset($cfg['max_clients']) ? $cfg['max_clients'] : '100';

        $toml .= "\n[server]\n";
        $toml .= "listen = \"{$listen_addr}:{$server_port}\"\n";
        $toml .= "max_clients = {$max_clients}\n";
    }

    // Client section.
    if ($mode === 'client') {
        $server_addr = isset($cfg['server_addr']) ? $cfg['server_addr'] : '';
        $server_port = isset($cfg['server_port']) ? $cfg['server_port'] : '51820';
        $psk = isset($cfg['psk']) ? $cfg['psk'] : '';

        if (!empty($server_addr)) {
            $toml .= "\n[client]\n";
            $toml .= "server = \"{$server_addr}:{$server_port}\"\n";
            if (!empty($psk)) {
                $toml .= "psk = \"{$psk}\"\n";
            }
        }
    }

    // Interface section.
    $tun_name = isset($cfg['tun_name']) ? $cfg['tun_name'] : 'desmos0';
    $tun_mtu = isset($cfg['tun_mtu']) ? $cfg['tun_mtu'] : '1420';
    $toml .= "\n[interface]\n";
    $toml .= "name = \"{$tun_name}\"\n";
    $toml .= "mtu = {$tun_mtu}\n";

    file_put_contents(DESMOS_CONF_FILE, $toml);
    chmod(DESMOS_CONF_FILE, 0600);
}

/**
 * Write the FreeBSD rc.d script.
 */
function desmos_write_rcscript() {
    $rc = <<<'RCEOF'
#!/bin/sh

# PROVIDE: desmos
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="desmos"
rcvar="desmos_enable"
command="/usr/local/bin/desmos"
command_args="up -c /usr/local/etc/desmos/desmos.toml"
pidfile="/var/run/desmos.pid"

start_cmd="desmos_start"
stop_cmd="desmos_stop"

desmos_start() {
    echo "Starting ${name}."
    /usr/sbin/daemon -f -p ${pidfile} ${command} ${command_args}
}

desmos_stop() {
    if [ -f "${pidfile}" ]; then
        echo "Stopping ${name}."
        kill $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    fi
    /usr/local/bin/desmos down 2>/dev/null || true
}

load_rc_config $name
run_rc_command "$1"
RCEOF;

    file_put_contents(DESMOS_RC_SCRIPT, $rc);
    chmod(DESMOS_RC_SCRIPT, 0755);
}

/**
 * Start the desmos service.
 */
function desmos_start() {
    mwexec(DESMOS_RC_SCRIPT . ' start');
}

/**
 * Stop the desmos service.
 */
function desmos_stop() {
    mwexec(DESMOS_RC_SCRIPT . ' stop');
}

/**
 * Restart the desmos service.
 */
function desmos_restart() {
    desmos_stop();
    sleep(1);
    desmos_start();
}

/**
 * Check if desmos is running.
 */
function desmos_is_running() {
    return is_process_running('desmos');
}
