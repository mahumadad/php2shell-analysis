#!/bin/bash
# check_mitigation.sh — Verifica la mitigación de PHP2Shell en servidores LiteSpeed
#
# Chequea:
# 1. session.upload_progress.enabled en cada PHP instalado
# 2. Si la setting puede ser overrideada por .user.ini / .htaccess
# 3. Si el guard extension está presente
# 4. Versión de PHP (parcheada o no)
# 5. Configuración de php_admin_flag en pools FPM

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "=== PHP2Shell Mitigation Check ==="
echo "=== CVE-2026-109618 / CVE-2026-109619 ==="
echo ""

FIXED_VERSIONS=(
    "8.2.35"
    "8.3.36"
    "8.4.27"
    "8.5.12"
)

version_ge() {
    # Returns 0 if $1 >= $2
    printf '%s\n%s' "$2" "$1" | sort -V -C
}

check_php_binary() {
    local php="$1"
    local label="$2"

    if [[ ! -x "$php" ]]; then
        return
    fi

    local version
    version=$("$php" -r 'echo PHP_VERSION;' 2>/dev/null) || return

    echo "--- $label ($php) ---"
    echo "  Version: $version"

    # Check si es versión parcheada
    local patched=false
    for fv in "${FIXED_VERSIONS[@]}"; do
        local major_minor="${version%.*}"
        local fv_major_minor="${fv%.*}"
        if [[ "$major_minor" == "$fv_major_minor" ]] && version_ge "$version" "$fv"; then
            patched=true
            break
        fi
    done

    if $patched; then
        echo -e "  Patch status: ${GREEN}PATCHED${NC} (>= $fv)"
    else
        # Check EOL
        local major="${version%%.*}"
        local minor="${version#*.}"
        minor="${minor%%.*}"
        if [[ "$major" -lt 8 ]] || { [[ "$major" -eq 8 ]] && [[ "$minor" -le 1 ]]; }; then
            echo -e "  Patch status: ${RED}EOL — no habrá parche oficial${NC}"
        else
            echo -e "  Patch status: ${YELLOW}NO PARCHEADO — actualizar ASAP${NC}"
        fi
    fi

    # Check upload_progress.enabled
    local up_enabled
    up_enabled=$("$php" -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null) || up_enabled="unknown"
    if [[ "$up_enabled" == "1" ]] || [[ "$up_enabled" == "On" ]]; then
        echo -e "  upload_progress.enabled: ${RED}ON (VULNERABLE)${NC}"
    elif [[ "$up_enabled" == "" ]] || [[ "$up_enabled" == "0" ]] || [[ "$up_enabled" == "Off" ]]; then
        echo -e "  upload_progress.enabled: ${GREEN}OFF (mitigado)${NC}"
    else
        echo -e "  upload_progress.enabled: ${YELLOW}$up_enabled${NC}"
    fi

    # Check INI scope (PERDIR = overrideable por .user.ini/.htaccess)
    local ini_access
    ini_access=$("$php" -r '
        $all = ini_get_all("session");
        if (isset($all["session.upload_progress.enabled"])) {
            $a = $all["session.upload_progress.enabled"]["access"];
            if ($a & INI_USER) echo "USER+PERDIR (overrideable!)";
            elseif ($a & INI_PERDIR) echo "PERDIR (overrideable por .user.ini)";
            elseif ($a & INI_SYSTEM) echo "SYSTEM (solo php.ini/pool)";
            else echo "access=$a";
        } else {
            echo "not found";
        }
    ' 2>/dev/null) || ini_access="unknown"

    if [[ "$ini_access" == *"overrideable"* ]]; then
        echo -e "  INI scope: ${YELLOW}$ini_access${NC}"
        echo -e "  ${YELLOW}→ Un .user.ini malicioso puede re-habilitarlo${NC}"
        echo -e "  ${YELLOW}→ Usar php_admin_flag en pool FPM para prevenirlo${NC}"
    else
        echo -e "  INI scope: $ini_access"
    fi

    # Check guard extension
    local guard_loaded
    guard_loaded=$("$php" -m 2>/dev/null | grep -ci "hp_uploadprogress_guard") || true
    if [[ "$guard_loaded" -gt 0 ]]; then
        echo -e "  Guard extension: ${GREEN}LOADED${NC}"
        "$php" --ri hp_uploadprogress_guard 2>/dev/null | grep -i "detach\|callback" || true
    else
        echo -e "  Guard extension: not loaded"
    fi

    # Check use_strict_mode
    local strict
    strict=$("$php" -r 'echo ini_get("session.use_strict_mode");' 2>/dev/null) || strict="unknown"
    if [[ "$strict" == "1" ]] || [[ "$strict" == "On" ]]; then
        echo -e "  use_strict_mode: ${GREEN}ON${NC}"
    else
        echo -e "  use_strict_mode: ${YELLOW}OFF — habilitar como hardening adicional${NC}"
    fi

    # Check serialize_handler (CVE-2026-109618: handler mismatch)
    local serializer
    serializer=$("$php" -r 'echo ini_get("session.serialize_handler");' 2>/dev/null) || serializer="unknown"
    echo "  serialize_handler: $serializer"

    echo ""
}

# Buscar binarios PHP
echo "[*] Buscando binarios PHP..."
echo ""

# LiteSpeed php binaries
for lsphp in /usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp; do
    [[ -x "$lsphp" ]] && check_php_binary "$lsphp" "LiteSpeed $(basename $(dirname $(dirname $lsphp)))"
done

# System php
for sysphp in /usr/bin/php /usr/local/bin/php; do
    [[ -x "$sysphp" ]] && check_php_binary "$sysphp" "System PHP"
done

# cPanel EA4
for eaphp in /opt/cpanel/ea-php*/root/usr/bin/php; do
    [[ -x "$eaphp" ]] && check_php_binary "$eaphp" "cPanel $(basename $(dirname $(dirname $(dirname $(dirname $eaphp)))))"
done

# Sury / Ondrej
for suryphp in /usr/bin/php*.* ; do
    [[ -x "$suryphp" ]] && check_php_binary "$suryphp" "Sury $(basename $suryphp)"
done

# Check FPM pool configs para php_admin_flag
echo "[*] Buscando php_admin_flag en pools FPM..."
for pooldir in /etc/php/*/fpm/pool.d /usr/local/lsws/lsphp*/etc/php/*/litespeed /opt/cpanel/ea-php*/root/etc/php-fpm.d; do
    if [[ -d "$pooldir" ]]; then
        echo "  Scanning: $pooldir"
        if grep -rl "upload_progress" "$pooldir" 2>/dev/null; then
            grep -rn "upload_progress" "$pooldir" 2>/dev/null | while read -r line; do
                if echo "$line" | grep -q "php_admin_flag"; then
                    echo -e "    ${GREEN}$line${NC}"
                elif echo "$line" | grep -q "php_flag"; then
                    echo -e "    ${YELLOW}$line (php_flag es overrideable, usar php_admin_flag)${NC}"
                fi
            done
        else
            echo -e "    ${YELLOW}No upload_progress override found${NC}"
        fi
    fi
done

# CVE-2026-109618: Check per-directory serializer mismatch
echo ""
echo "[*] Buscando mismatch de session.serialize_handler (CVE-2026-109618)..."
serializers_found=()
for confdir in /etc/php/*/fpm/pool.d /etc/php/*/cli/conf.d /etc/php/*/fpm/conf.d /usr/local/lsws/lsphp*/etc/php/*/litespeed; do
    if [[ -d "$confdir" ]]; then
        hits=$(grep -rn "serialize_handler" "$confdir" 2>/dev/null) || true
        if [[ -n "$hits" ]]; then
            echo "  $confdir:"
            echo "$hits" | while read -r line; do
                echo "    $line"
            done
        fi
    fi
done

# Check .user.ini files that could override serializer
echo ""
echo "[*] Buscando .user.ini/.htaccess con serialize_handler override..."
for webroot in /var/www /home/*/public_html /usr/local/lsws/Example/html; do
    if [[ -d "$webroot" ]]; then
        find "$webroot" -maxdepth 3 -name ".user.ini" -o -name ".htaccess" 2>/dev/null | while read -r f; do
            if grep -q "serialize_handler" "$f" 2>/dev/null; then
                echo -e "  ${RED}ALERTA: $f contiene override de serialize_handler${NC}"
                grep "serialize_handler" "$f"
            fi
        done
    fi
done

echo ""
echo "=== Resumen ==="
echo ""
echo "--- CVE-2026-109619 (upload_progress UAF) ---"
echo "Mitigación mínima: session.upload_progress.enabled = Off en php.ini"
echo "Mitigación robusta: php_admin_flag[session.upload_progress.enabled] = off en pool FPM"
echo "Mitigación máxima: Guard extension (no overrideable) + parche PHP"
echo ""
echo "--- CVE-2026-109618 (serializer mismatch + __destruct) ---"
echo "Mitigación: session.serialize_handler IDÉNTICO en todos los directorios"
echo "            session.use_strict_mode = On"
echo "            No usar .user.ini para override de serialize_handler"
echo "            NOTA: deshabilitar upload_progress NO mitiga esta cadena"
echo ""
echo "Fix definitivo: Actualizar a PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
