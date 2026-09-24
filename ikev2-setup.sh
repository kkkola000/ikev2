#!/usr/bin/env bash
#
# ikev2-setup.sh — развёртывание IKEv2 VPN-сервера (strongSwan + swanctl)
# на Ubuntu 24.04.
#
# Аутентификация: сертификат сервера (собственный CA или Let's Encrypt)
# + логин/пароль пользователя (EAP-MSCHAPv2). Поддерживаются встроенные
# клиенты Windows 10/11, macOS, iOS, Android (strongSwan / встроенный IKEv2).
#
# После установки скрипт копируется в /usr/local/sbin/ikev2-vpn, и дальше
# управлять сервером можно командой `ikev2-vpn` (см. `ikev2-vpn --help`).

set -Eeuo pipefail
umask 077

readonly SCRIPT_VERSION="1.0.0"

# --- Пути -------------------------------------------------------------------
readonly STATE_DIR=/etc/ikev2
readonly STATE_FILE=$STATE_DIR/ikev2.env
readonly USERS_DB=$STATE_DIR/users
readonly PKI_DIR=$STATE_DIR/pki
readonly CA_KEY=$PKI_DIR/ca-key.pem
readonly CLIENTS_DIR=/root/ikev2-clients

readonly SWANCTL_DIR=/etc/swanctl
readonly CONN_CONF=$SWANCTL_DIR/conf.d/ikev2-vpn.conf
readonly SECRETS_CONF=$SWANCTL_DIR/conf.d/ikev2-vpn-secrets.conf
readonly CA_CERT=$SWANCTL_DIR/x509ca/ikev2-vpn-ca.pem
readonly SERVER_CERT=$SWANCTL_DIR/x509/ikev2-vpn-server.pem
readonly SERVER_KEY=$SWANCTL_DIR/private/ikev2-vpn-server.pem

readonly STRONGSWAN_CONF=/etc/strongswan.d/ikev2-vpn.conf
readonly SYSCTL_CONF=/etc/sysctl.d/60-ikev2-vpn.conf
readonly FW_SCRIPT=/usr/local/sbin/ikev2-vpn-firewall
readonly FW_UNIT=/etc/systemd/system/ikev2-vpn-firewall.service
readonly SELF_BIN=/usr/local/sbin/ikev2-vpn

readonly LE_NAME=ikev2-vpn
readonly LE_HOOK=/etc/letsencrypt/renewal-hooks/deploy/ikev2-vpn.sh

readonly CONN_NAME=ikev2-vpn

# Алгоритмы. Первым идёт вариант с DH (PFS при rekey), вторым — без DH,
# чтобы клиенты без PFS (Windows) тоже могли пересогласовать ключи.
readonly IKE_PROPOSALS="aes256gcm16-aes128gcm16-prfsha512-prfsha384-prfsha256-curve25519-ecp384-ecp256-modp3072-modp2048, aes256-aes128-sha512-sha384-sha256-sha1-curve25519-ecp384-ecp256-modp3072-modp2048"
readonly ESP_PROPOSALS="aes256gcm16-aes128gcm16-chacha20poly1305-curve25519-ecp384-ecp256-modp3072-modp2048, aes256gcm16-aes128gcm16-chacha20poly1305, aes256-aes128-sha512-sha384-sha256-sha1-curve25519-ecp384-ecp256-modp3072-modp2048, aes256-aes128-sha512-sha384-sha256-sha1"

readonly PACKAGES=(
    charon-systemd strongswan-swanctl strongswan-pki
    libstrongswan-standard-plugins libcharon-extra-plugins libcharon-extauth-plugins
    iptables iproute2 openssl curl ca-certificates
)

# --- Вывод ------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\e[31m' C_GRN=$'\e[32m' C_YEL=$'\e[33m' C_BLD=$'\e[1m' C_RST=$'\e[0m'
else
    C_RED='' C_GRN='' C_YEL='' C_BLD='' C_RST=''
fi

info() { printf '%s==>%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

trap 'die "Ошибка в строке $LINENO: $BASH_COMMAND"' ERR

usage() {
    cat <<EOF
IKEv2 VPN (strongSwan) для Ubuntu 24.04, версия $SCRIPT_VERSION

Использование: $(basename "$0") [команда] [параметры]

Команды:
  install                  установить или перенастроить сервер (по умолчанию)
  add-user ИМЯ [ПАРОЛЬ]    добавить пользователя (без пароля — сгенерировать)
  del-user ИМЯ             удалить пользователя и разорвать его подключения
  passwd ИМЯ [ПАРОЛЬ]      сменить пароль (без пароля — сгенерировать)
  list-users               список пользователей
  profiles [ИМЯ]           пересоздать клиентские профили (всех или одного)
  status                   состояние сервера и активные подключения
  uninstall                удалить VPN-сервер

Параметры install:
  --host АДРЕС             домен или публичный IPv4 сервера
                           (по умолчанию определяется автоматически)
  --letsencrypt            сертификат Let's Encrypt (нужен домен и порт 80/tcp)
  --self-signed            собственный CA (по умолчанию)
  --email EMAIL            email для Let's Encrypt (необязательно)
  --user ИМЯ               первый пользователь (по умолчанию vpnuser)
  --password ПАРОЛЬ        его пароль (по умолчанию генерируется)
  --dns СПИСОК             DNS для клиентов через запятую
                           (по умолчанию 1.1.1.1,1.0.0.1)
  --pool CIDR              IPv4-подсеть для клиентов (по умолчанию 10.10.10.0/24)
  --ipv6 | --no-ipv6       IPv6 в туннеле (по умолчанию — если у сервера есть IPv6)

Параметры uninstall:
  --purge                  удалить также пакеты strongSwan

Скрипт ничего не спрашивает: всё, что не задано параметрами, берётся
из предыдущей установки или определяется автоматически.

Примеры:
  sudo bash $(basename "$0")
  sudo bash $(basename "$0") --host vpn.example.com --letsencrypt --email me@example.com
  sudo ikev2-vpn add-user alice
EOF
}

# --- Проверки значений -------------------------------------------------------
is_ipv4() {
    local o='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    [[ $1 =~ ^$o\.$o\.$o\.$o$ ]]
}

is_ipv6() {
    [[ $1 == *:* && $1 =~ ^[0-9A-Fa-f:.]+$ ]]
}

is_fqdn() {
    [[ ${#1} -le 253 && $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}$ ]]
}

is_private_cidr4() {
    local ip=${1%/*} len=${1#*/}
    [[ $1 == */* && $len =~ ^[0-9]+$ ]] && is_ipv4 "$ip" || return 1
    ((len >= 16 && len <= 29)) || return 1
    [[ $ip =~ ^10\. || $ip =~ ^192\.168\. || $ip =~ ^172\.(1[6-9]|2[0-9]|3[01])\. || $ip =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]
}

valid_username() {
    [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$ ]]
}

# Пароль попадает в swanctl.conf в двойных кавычках, поэтому запрещаем
# кавычку, обратный слэш и управляющие символы; только печатный ASCII.
valid_password() {
    local LC_ALL=C re='^[ -~]+$'
    [[ ${#1} -ge 8 && ${#1} -le 128 ]] || return 1
    [[ $1 =~ $re ]] || return 1
    [[ $1 != *[\"\\]* ]]
}

gen_password() {
    local p
    p=$(openssl rand -base64 48)
    p=${p//[^A-Za-z0-9]/}
    printf '%s' "${p:0:20}"
}

gen_uuid() {
    local u
    u=$(</proc/sys/kernel/random/uuid)
    printf '%s' "${u^^}"
}

xml_escape() {
    local s=$1
    s=${s//&/&amp;}
    s=${s//</&lt;}
    s=${s//>/&gt;}
    s=${s//\"/&quot;}
    s=${s//\'/&apos;}
    printf '%s' "$s"
}

# --- Окружение -------------------------------------------------------------
require_root() {
    [[ $EUID -eq 0 ]] || die "Запустите скрипт от root (через sudo)."
}

check_os() {
    local id="" ver=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        id=$(. /etc/os-release && echo "${ID:-}")
        # shellcheck disable=SC1091
        ver=$(. /etc/os-release && echo "${VERSION_ID:-}")
    fi
    if [[ $id != ubuntu || $ver != 24.04 ]]; then
        warn "Скрипт рассчитан на Ubuntu 24.04, обнаружено: ${id:-?} ${ver:-?}. Продолжаю."
    fi
    command -v systemctl >/dev/null || die "Нужен systemd."

    local virt
    virt=$(systemd-detect-virt 2>/dev/null || true)
    case $virt in
        openvz | lxc | lxc-libvirt)
            warn "Сервер работает в контейнере ($virt): IPsec в ядре там обычно недоступен."
            ;;
    esac
}

# Значение после ключевого слова $1 в первой строке stdin (без раннего exit,
# чтобы при pipefail писатель не получил SIGPIPE).
first_field_after() {
    awk -v k="$1" '!done { for (i = 1; i < NF; i++) if ($i == k) { print $(i + 1); done = 1; break } }'
}

default_iface6() {
    ip -6 route show default 2>/dev/null | first_field_after dev
}

server_has_ipv6() {
    [[ -d /proc/sys/net/ipv6 && -n $(default_iface6) && -n $(ip -6 addr show scope global 2>/dev/null) ]]
}

detect_public_ip() {
    local ip url
    for url in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        if command -v curl >/dev/null; then
            ip=$(curl -4 -fsS --max-time 5 "$url" 2>/dev/null) || ip=
        elif command -v wget >/dev/null; then
            ip=$(wget -4 -qO- --timeout=5 "$url" 2>/dev/null) || ip=
        else
            break
        fi
        ip=${ip//[[:space:]]/}
        if is_ipv4 "$ip"; then
            printf '%s' "$ip"
            return 0
        fi
    done
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | first_field_after src) || ip=
    if is_ipv4 "$ip"; then
        printf '%s' "$ip"
    fi
}

gen_ula_pool() {
    local b
    read -r -a b < <(od -An -N5 -tx1 /dev/urandom)
    printf 'fd%s:%s%s:%s%s::/112' "${b[@]}"
}

load_state() {
    [[ -f $STATE_FILE ]] || return 1
    # shellcheck disable=SC1090
    . "$STATE_FILE"
}

require_installed() {
    load_state || die "VPN-сервер не установлен. Сначала выполните: $0 install"
}

save_state() {
    install -d -m 700 "$STATE_DIR"
    {
        echo "# Параметры IKEv2 VPN (ikev2-vpn). Используются скриптом и правилами файрвола."
        printf 'IKEV2_HOST=%q\n' "$IKEV2_HOST"
        printf 'IKEV2_CERT_MODE=%q\n' "$IKEV2_CERT_MODE"
        printf 'IKEV2_LE_EMAIL=%q\n' "$IKEV2_LE_EMAIL"
        printf 'IKEV2_POOL4=%q\n' "$IKEV2_POOL4"
        printf 'IKEV2_POOL6=%q\n' "$IKEV2_POOL6"
        printf 'IKEV2_DNS=%q\n' "$IKEV2_DNS"
    } >"$STATE_FILE.tmp"
    chmod 600 "$STATE_FILE.tmp"
    mv -f "$STATE_FILE.tmp" "$STATE_FILE"
}

strongswan_active() {
    systemctl is-active --quiet strongswan.service
}

# --- Пользователи ----------------------------------------------------------
user_exists() {
    [[ -f $USERS_DB ]] && awk -F: -v u="$1" '$1 == u { f = 1 } END { exit !f }' "$USERS_DB"
}

user_password() {
    awk -F: -v u="$1" '$1 == u { sub(/^[^:]*:/, ""); print; exit }' "$USERS_DB"
}

list_user_names() {
    [[ -f $USERS_DB ]] || return 0
    awk -F: 'NF { print $1 }' "$USERS_DB"
}

db_set_user() { # db_set_user ИМЯ ПАРОЛЬ
    local tmp
    install -d -m 700 "$STATE_DIR"
    tmp=$(mktemp "$STATE_DIR/.users.XXXXXX")
    if [[ -f $USERS_DB ]]; then
        awk -F: -v u="$1" 'NF && $1 != u' "$USERS_DB" >"$tmp"
    fi
    printf '%s:%s\n' "$1" "$2" >>"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$USERS_DB"
}

db_del_user() {
    local tmp
    tmp=$(mktemp "$STATE_DIR/.users.XXXXXX")
    awk -F: -v u="$1" 'NF && $1 != u' "$USERS_DB" >"$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$USERS_DB"
}

write_secrets() {
    local name pass n=0
    {
        echo "# Сгенерировано ikev2-vpn из $USERS_DB — не редактируйте вручную,"
        echo "# используйте: ikev2-vpn add-user | del-user | passwd"
        echo "secrets {"
        if [[ -f $USERS_DB ]]; then
            while IFS=: read -r name pass; do
                [[ -n $name ]] || continue
                n=$((n + 1))
                printf '    eap-user%d {\n        id = "%s"\n        secret = "%s"\n    }\n' \
                    "$n" "$name" "$pass"
            done <"$USERS_DB"
        fi
        echo "}"
    } >"$SECRETS_CONF.tmp"
    chmod 600 "$SECRETS_CONF.tmp"
    mv -f "$SECRETS_CONF.tmp" "$SECRETS_CONF"
}

reload_creds() {
    write_secrets
    if strongswan_active; then
        swanctl --load-creds --noprompt >/dev/null
    fi
}

# Номера IKE_SA, у которых EAP-идентификатор равен $1.
ike_sa_ids_for_user() {
    swanctl --list-sas 2>/dev/null | awk -v u="$1" '
        /^[^ ].*: #[0-9]+,/ { id = $2; sub(/^#/, "", id); sub(/,$/, "", id) }
        /^  remote / && index($0, "EAP: '\''" u "'\''") { print id }
    ' | sort -u
}

terminate_user_sessions() {
    local id
    strongswan_active || return 0
    for id in $(ike_sa_ids_for_user "$1"); do
        swanctl --terminate --ike-id "$id" --force --timeout 5 >/dev/null 2>&1 || true
    done
}

# --- Сертификаты -----------------------------------------------------------
ca_common_name() {
    openssl x509 -in "$CA_CERT" -noout -subject -nameopt sep_multiline,utf8 |
        sed -n 's/^ *CN=//p'
}

ensure_ca() {
    install -d -m 700 "$PKI_DIR"
    if [[ -f $CA_KEY && -f $CA_CERT ]]; then
        info "Используется существующий CA: $(ca_common_name)"
        return
    fi
    local suffix
    suffix=$(openssl rand -hex 4)
    info "Создание собственного центра сертификации (CA)"
    pki --gen --type rsa --size 4096 --outform pem >"$CA_KEY"
    chmod 600 "$CA_KEY"
    pki --self --ca --lifetime 3650 --in "$CA_KEY" --type rsa \
        --dn "CN=IKEv2 VPN CA $suffix" --outform pem >"$CA_CERT.tmp"
    chmod 644 "$CA_CERT.tmp"
    mv -f "$CA_CERT.tmp" "$CA_CERT"
}

issue_selfsigned_server_cert() {
    ensure_ca
    info "Выпуск сертификата сервера для $IKEV2_HOST"
    local key_tmp=$PKI_DIR/server-key.pem.tmp cert_tmp=$PKI_DIR/server-cert.pem.tmp
    pki --gen --type rsa --size 3072 --outform pem >"$key_tmp"
    pki --issue --lifetime 3650 --cacert "$CA_CERT" --cakey "$CA_KEY" \
        --in "$key_tmp" --type rsa --dn "CN=$IKEV2_HOST" --san "$IKEV2_HOST" \
        --flag serverAuth --flag ikeIntermediate --outform pem >"$cert_tmp"
    install -m 600 "$key_tmp" "$SERVER_KEY"
    install -m 644 "$cert_tmp" "$SERVER_CERT"
    rm -f "$key_tmp" "$cert_tmp" "$SWANCTL_DIR"/x509ca/ikev2-vpn-le-*.pem
}

write_le_hook() {
    install -d -m 755 "$(dirname "$LE_HOOK")"
    cat >"$LE_HOOK" <<EOF
#!/bin/bash
# Сгенерировано ikev2-vpn: после выпуска/продления сертификата Let's Encrypt
# копирует его в strongSwan и перезагружает учётные данные.
set -euo pipefail
lineage=\${RENEWED_LINEAGE:-/etc/letsencrypt/live/$LE_NAME}
[[ \$(basename "\$lineage") == "$LE_NAME" ]] || exit 0
install -m 600 "\$lineage/privkey.pem" "$SERVER_KEY"
install -m 644 "\$lineage/cert.pem" "$SERVER_CERT"
rm -f "$SWANCTL_DIR"/x509ca/ikev2-vpn-le-*.pem
awk -v dir="$SWANCTL_DIR/x509ca" '
    /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/ikev2-vpn-le-%d.pem", dir, n) }
    f { print > f }
    /-----END CERTIFICATE-----/ { close(f); f = "" }
' "\$lineage/chain.pem"
chmod 644 "$SWANCTL_DIR"/x509ca/ikev2-vpn-le-*.pem
if systemctl is-active --quiet strongswan.service; then
    swanctl --load-creds --noprompt >/dev/null
fi
EOF
    chmod 755 "$LE_HOOK"
}

issue_letsencrypt_cert() {
    info "Установка certbot"
    apt_install certbot

    local listeners
    listeners=$(ss -Hltnp 'sport = :80' 2>/dev/null || true)
    if [[ -n $listeners ]]; then
        die "Порт 80/tcp занят (нужен certbot для проверки домена):
$listeners
Остановите веб-сервер на время установки или используйте --self-signed."
    fi

    local email_args=(--register-unsafely-without-email)
    [[ -n $IKEV2_LE_EMAIL ]] && email_args=(-m "$IKEV2_LE_EMAIL")

    info "Получение сертификата Let's Encrypt для $IKEV2_HOST"
    certbot certonly --standalone --non-interactive --agree-tos "${email_args[@]}" \
        --preferred-challenges http --cert-name "$LE_NAME" -d "$IKEV2_HOST" \
        --key-type rsa --rsa-key-size 3072 --keep-until-expiring ||
        die "certbot не смог получить сертификат. Проверьте, что A-запись $IKEV2_HOST
указывает на этот сервер и порт 80/tcp открыт в панели хостинга."

    write_le_hook
    RENEWED_LINEAGE=/etc/letsencrypt/live/$LE_NAME "$LE_HOOK"
}

# --- Конфигурация ----------------------------------------------------------
write_swanctl_conf() {
    local pools=ikev2-vpn-pool4 local_ts=0.0.0.0/0 dns
    if [[ -n $IKEV2_POOL6 ]]; then
        pools+=", ikev2-vpn-pool6"
        local_ts+=", ::/0"
    fi
    dns=${IKEV2_DNS//,/, }

    {
        cat <<EOF
# Сгенерировано ikev2-setup.sh $SCRIPT_VERSION. При повторном запуске install
# файл будет перезаписан.

connections {
    $CONN_NAME {
        version = 2
        proposals = $IKE_PROPOSALS
        pools = $pools
        send_cert = always
        # Один логин можно использовать на нескольких устройствах.
        unique = never
        fragmentation = yes
        # Всегда инкапсулировать ESP в UDP 4500: так VPN проходит через NAT
        # и файрволы провайдеров, которые режут протокол ESP.
        encap = yes
        dpd_delay = 60s
        # Ключи пересогласовывает клиент (Windows плохо переносит rekey от сервера).
        rekey_time = 0s

        local {
            auth = pubkey
            certs = $(basename "$SERVER_CERT")
            id = $IKEV2_HOST
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            $CONN_NAME {
                local_ts = $local_ts
                esp_proposals = $ESP_PROPOSALS
                rekey_time = 0s
                dpd_action = clear
            }
        }
    }
}

pools {
    ikev2-vpn-pool4 {
        addrs = $IKEV2_POOL4
        dns = $dns
    }
EOF
        if [[ -n $IKEV2_POOL6 ]]; then
            cat <<EOF
    ikev2-vpn-pool6 {
        addrs = $IKEV2_POOL6
    }
EOF
        fi
        echo "}"
    } >"$CONN_CONF.tmp"
    chmod 600 "$CONN_CONF.tmp"
    mv -f "$CONN_CONF.tmp" "$CONN_CONF"
}

# swanctl и pki по умолчанию пытаются загрузить все плагины, с которыми собран
# strongSwan, включая отсутствующие libstrongswan-extra-plugins, и засоряют вывод
# ошибками. Оставляем им только плагины из libstrongswan и
# libstrongswan-standard-plugins (порядок — как в штатном списке).
write_strongswan_conf() {
    local plugins="aesni aes rc2 sha2 sha1 md5 mgf1 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp agent xcbc hmac kdf gcm drbg"
    cat >"$STRONGSWAN_CONF" <<EOF
# Сгенерировано ikev2-vpn: список плагинов для утилит swanctl и pki.
swanctl {
    load = $plugins
}
pki {
    load = $plugins
}
EOF
    chmod 644 "$STRONGSWAN_CONF"
}

write_sysctl() {
    {
        echo "# IKEv2 VPN (ikev2-vpn)"
        echo "net.ipv4.ip_forward = 1"
        echo "net.ipv4.conf.all.accept_redirects = 0"
        echo "net.ipv4.conf.default.accept_redirects = 0"
        echo "net.ipv4.conf.all.send_redirects = 0"
        echo "net.ipv4.conf.default.send_redirects = 0"
        if [[ -n $IKEV2_POOL6 ]]; then
            echo "net.ipv6.conf.all.forwarding = 1"
            echo "net.ipv6.conf.default.forwarding = 1"
            echo "net.ipv6.conf.all.accept_redirects = 0"
            echo "net.ipv6.conf.default.accept_redirects = 0"
            # С forwarding=1 ядро перестаёт принимать RA, если accept_ra=1.
            # Если адрес IPv6 получен через RA ядром (не systemd-networkd), нужно 2.
            local if6
            if6=$(default_iface6)
            if [[ -n $if6 && $if6 != *.* && -r /proc/sys/net/ipv6/conf/$if6/accept_ra &&
                $(</proc/sys/net/ipv6/conf/"$if6"/accept_ra) == 1 ]]; then
                echo "net.ipv6.conf.$if6.accept_ra = 2"
            fi
        fi
    } >"$SYSCTL_CONF"
    chmod 644 "$SYSCTL_CONF"
    sysctl -q -p "$SYSCTL_CONF" >/dev/null
}

write_firewall() {
    cat >"$FW_SCRIPT" <<'EOF'
#!/bin/bash
# Правила iptables для IKEv2 VPN (сгенерировано ikev2-vpn).
# Правила живут в отдельных цепочках IKEV2-* и вставляются в начало
# встроенных цепочек, поэтому работают вместе с UFW и Docker.
#   ikev2-vpn-firewall start|stop
set -euo pipefail

# shellcheck disable=SC1091
. /etc/ikev2/ikev2.env

HOOKS=("filter INPUT" "filter FORWARD" "nat POSTROUTING" "mangle FORWARD")

fw_clear() { # fw_clear iptables|ip6tables
    local cmd=$1 spec table chain
    for spec in "${HOOKS[@]}"; do
        read -r table chain <<<"$spec"
        while "$cmd" -w -t "$table" -D "$chain" -j "IKEV2-$chain" 2>/dev/null; do :; done
        "$cmd" -w -t "$table" -F "IKEV2-$chain" 2>/dev/null || true
        "$cmd" -w -t "$table" -X "IKEV2-$chain" 2>/dev/null || true
    done
}

fw_setup() { # fw_setup iptables|ip6tables ПУЛ MSS
    local cmd=$1 pool=$2 mss=$3 spec table chain
    for spec in "${HOOKS[@]}"; do
        read -r table chain <<<"$spec"
        "$cmd" -w -t "$table" -N "IKEV2-$chain"
    done

    # IKE и NAT-T (ESP — на случай клиентов без инкапсуляции).
    "$cmd" -w -A IKEV2-INPUT -p udp -m multiport --dports 500,4500 -j ACCEPT
    "$cmd" -w -A IKEV2-INPUT -p esp -j ACCEPT
    if [[ $IKEV2_CERT_MODE == letsencrypt ]]; then
        # certbot --standalone при продлении сертификата.
        "$cmd" -w -A IKEV2-INPUT -p tcp --dport 80 -j ACCEPT
    fi

    # Пропускаем трафик клиентов, пришедший/уходящий через IPsec.
    "$cmd" -w -A IKEV2-FORWARD -s "$pool" -m policy --dir in --pol ipsec -j ACCEPT
    "$cmd" -w -A IKEV2-FORWARD -d "$pool" -m policy --dir out --pol ipsec -j ACCEPT

    # NAT в интернет (кроме трафика, который снова уходит в IPsec).
    "$cmd" -w -t nat -A IKEV2-POSTROUTING -s "$pool" -m policy --dir out --pol ipsec -j ACCEPT
    "$cmd" -w -t nat -A IKEV2-POSTROUTING -s "$pool" -j MASQUERADE

    # Уменьшаем MSS, чтобы TCP-пакеты не фрагментировались внутри туннеля.
    "$cmd" -w -t mangle -A IKEV2-FORWARD -s "$pool" -m policy --dir in --pol ipsec \
        -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss "$((mss + 1)):65535" -j TCPMSS --set-mss "$mss"
    "$cmd" -w -t mangle -A IKEV2-FORWARD -d "$pool" -m policy --dir out --pol ipsec \
        -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss "$((mss + 1)):65535" -j TCPMSS --set-mss "$mss"

    for spec in "${HOOKS[@]}"; do
        read -r table chain <<<"$spec"
        "$cmd" -w -t "$table" -I "$chain" 1 -j "IKEV2-$chain"
    done
}

case ${1:-} in
    start)
        fw_clear iptables
        fw_clear ip6tables
        fw_setup iptables "$IKEV2_POOL4" 1340
        if [[ -n ${IKEV2_POOL6:-} ]]; then
            fw_setup ip6tables "$IKEV2_POOL6" 1320
        fi
        ;;
    stop)
        fw_clear iptables
        fw_clear ip6tables
        ;;
    *)
        echo "Использование: $0 start|stop" >&2
        exit 2
        ;;
esac
EOF
    chmod 755 "$FW_SCRIPT"

    cat >"$FW_UNIT" <<EOF
[Unit]
Description=IKEv2 VPN firewall rules (iptables)
After=network-pre.target ufw.service nftables.service netfilter-persistent.service firewalld.service docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$FW_SCRIPT start
ExecReload=$FW_SCRIPT start
ExecStop=$FW_SCRIPT stop

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$FW_UNIT"
    systemctl daemon-reload
}

apply_firewall() {
    save_state
    write_firewall
    systemctl enable ikev2-vpn-firewall.service >/dev/null 2>&1
    systemctl restart ikev2-vpn-firewall.service
}

apt_install() {
    # needrestart в Ubuntu может показать интерактивный диалог после установки.
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1
    local missing=() p
    for p in "$@"; do
        [[ $(dpkg-query -W -f='${Status}' "$p" 2>/dev/null) == "install ok installed" ]] || missing+=("$p")
    done
    ((${#missing[@]})) || return 0
    if [[ -z ${APT_UPDATED:-} ]]; then
        apt-get update -q >/dev/null || warn "apt-get update завершился с ошибкой, пробую продолжить"
        APT_UPDATED=1
    fi
    apt-get install -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        "${missing[@]}" >/dev/null
}

check_conflicts() {
    # Старый способ запуска strongSwan (ipsec.conf) конфликтует с charon-systemd.
    if systemctl is-active --quiet strongswan-starter.service 2>/dev/null ||
        systemctl is-enabled --quiet strongswan-starter.service 2>/dev/null; then
        warn "Найден strongswan-starter (ipsec.conf) — он будет остановлен и отключён."
        systemctl disable --now strongswan-starter.service >/dev/null 2>&1 || true
    fi

    local busy
    busy=$(ss -Hlunp '( sport = :500 or sport = :4500 )' 2>/dev/null | grep -v '"charon' || true)
    if [[ -n $busy ]]; then
        die "UDP-порты 500/4500 уже заняты другим процессом (Libreswan, L2TP-сервер?):
$busy"
    fi

    if systemctl is-active --quiet firewalld.service 2>/dev/null; then
        warn "Активен firewalld: откройте в нём UDP 500 и 4500 и включите masquerade вручную."
    fi
}

check_pool_overlap() {
    local routes
    routes=$({
        ip -4 route show match "$IKEV2_POOL4" 2>/dev/null
        ip -4 route show root "$IKEV2_POOL4" 2>/dev/null
    } | grep -v '^default' || true)
    if [[ -n $routes ]]; then
        warn "Подсеть $IKEV2_POOL4 пересекается с сетями сервера:"
        printf '%s\n' "$routes" >&2
        warn "Укажите другую через --pool, если клиенты не смогут выходить в сеть."
    fi
}

# --- Клиентские профили ----------------------------------------------------
write_mobileconfig() { # write_mobileconfig USER PASS FILE
    local user pass file=$3 name host ca_cn="" ca_b64=""
    user=$(xml_escape "$1")
    pass=$(xml_escape "$2")
    host=$(xml_escape "$IKEV2_HOST")
    name=$(xml_escape "IKEv2 VPN ($IKEV2_HOST)")
    local uuid_vpn uuid_ca uuid_profile
    uuid_vpn=$(gen_uuid)
    uuid_ca=$(gen_uuid)
    uuid_profile=$(gen_uuid)

    if [[ $IKEV2_CERT_MODE == selfsigned ]]; then
        ca_cn=$(xml_escape "$(ca_common_name)")
        ca_b64=$(sed '/-----/d' "$CA_CERT" | tr -d '\n')
    fi

    {
        cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ExtendedAuthEnabled</key>
        <integer>1</integer>
        <key>AuthName</key>
        <string>$user</string>
        <key>AuthPassword</key>
        <string>$pass</string>
        <key>RemoteAddress</key>
        <string>$host</string>
        <key>RemoteIdentifier</key>
        <string>$host</string>
        <key>LocalIdentifier</key>
        <string>$user</string>
EOF
        if [[ -n $ca_cn ]]; then
            cat <<EOF
        <key>ServerCertificateIssuerCommonName</key>
        <string>$ca_cn</string>
EOF
        fi
        cat <<EOF
        <key>EnablePFS</key>
        <integer>1</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>480</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
        <key>OnDemandEnabled</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>IKEv2 VPN</string>
      <key>PayloadDisplayName</key>
      <string>$name</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$uuid_vpn</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$uuid_vpn</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>$name</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
EOF
        if [[ -n $ca_b64 ]]; then
            cat <<EOF
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>ikev2-vpn-ca.crt</string>
      <key>PayloadContent</key>
      <data>$ca_b64</data>
      <key>PayloadDescription</key>
      <string>IKEv2 VPN CA</string>
      <key>PayloadDisplayName</key>
      <string>$ca_cn</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.security.root.$uuid_ca</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>$uuid_ca</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
EOF
        fi
        cat <<EOF
  </array>
  <key>PayloadDisplayName</key>
  <string>$name</string>
  <key>PayloadIdentifier</key>
  <string>ikev2-vpn.$uuid_profile</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$uuid_profile</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF
    } >"$file"
}

write_sswan() { # write_sswan USER FILE
    local user=$1 file=$2 cert_line=""
    if [[ $IKEV2_CERT_MODE == selfsigned ]]; then
        cert_line=",
    \"cert\": \"$(sed '/-----/d' "$CA_CERT" | tr -d '\n')\""
    fi
    cat >"$file" <<EOF
{
  "uuid": "$(gen_uuid)",
  "name": "IKEv2 VPN ($IKEV2_HOST)",
  "type": "ikev2-eap",
  "remote": {
    "addr": "$IKEV2_HOST",
    "id": "$IKEV2_HOST"$cert_line
  },
  "local": {
    "eap_id": "$user"
  }
}
EOF
}

write_ps1() { # write_ps1 USER FILE
    local user=$1 file=$2
    {
        cat <<EOF
# IKEv2 VPN for Windows 10/11 (generated by ikev2-vpn).
# Run PowerShell as Administrator:
#   powershell -ExecutionPolicy Bypass -File .\\$user-windows.ps1
# Then connect: Settings -> Network & Internet -> VPN.
# User name: $user (the password is in README.txt).

\$ErrorActionPreference = 'Stop'
\$Name   = 'IKEv2 VPN ($IKEV2_HOST)'
\$Server = '$IKEV2_HOST'

EOF
        if [[ $IKEV2_CERT_MODE == selfsigned ]]; then
            cat <<'EOF'
# Trust the VPN server CA (Local Machine -> Trusted Root Certification Authorities).
$CaPem = @'
EOF
            cat "$CA_CERT"
            cat <<'EOF'
'@
$CaFile = Join-Path $env:TEMP 'ikev2-vpn-ca.crt'
Set-Content -Path $CaFile -Value $CaPem -Encoding Ascii
Import-Certificate -FilePath $CaFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Remove-Item $CaFile -Force

EOF
        fi
        cat <<'EOF'
if (Get-VpnConnection -AllUserConnection -Name $Name -ErrorAction SilentlyContinue) {
    Remove-VpnConnection -AllUserConnection -Name $Name -Force
}
Add-VpnConnection -AllUserConnection -Name $Name -ServerAddress $Server `
    -TunnelType Ikev2 -AuthenticationMethod Eap -EncryptionLevel Required `
    -RememberCredential -Force
# Strong ciphers instead of the Windows defaults (3DES / DH group 2).
Set-VpnConnectionIPsecConfiguration -AllUserConnection -ConnectionName $Name `
    -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 `
    -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 `
    -DHGroup Group14 -PfsGroup None -Force

Write-Host "VPN connection '$Name' has been created."
EOF
    } >"$file"
}

write_client_readme() { # write_client_readme USER PASS FILE
    local user=$1 pass=$2 file=$3 ca_note=""
    if [[ $IKEV2_CERT_MODE == selfsigned ]]; then
        ca_note="
Сервер использует собственный сертификат, поэтому при ручной настройке
сначала установите ikev2-vpn-ca.crt как корневой (доверенный) сертификат CA."
    fi
    cat >"$file" <<EOF
IKEv2 VPN — данные для подключения
==================================

Сервер:        $IKEV2_HOST
Удалённый ID:  $IKEV2_HOST
Логин:         $user
Пароль:        $pass
Тип:           IKEv2, аутентификация по логину/паролю (EAP-MSCHAPv2)
$ca_note

Файлы
-----
  $user.mobileconfig    iPhone/iPad/Mac: откройте файл, затем
                        «Настройки → Профиль загружен → Установить»
                        (на Mac: «Системные настройки → Профили»).
                        Внимание: внутри файла сохранён пароль.
  $user.sswan           Android: приложение strongSwan VPN Client
                        (Google Play / F-Droid) → меню → «Импорт профиля»,
                        при подключении введите пароль.
  $user-windows.ps1     Windows 10/11: запустите PowerShell от имени
                        администратора и выполните
                          powershell -ExecutionPolicy Bypass -File .\\$user-windows.ps1
                        затем «Параметры → Сеть и Интернет → VPN» → подключиться,
                        ввести логин и пароль.
EOF
    if [[ $IKEV2_CERT_MODE == selfsigned ]]; then
        cat >>"$file" <<EOF
  ikev2-vpn-ca.crt      сертификат CA для ручной настройки (Android без
                        приложения strongSwan, Linux и т.д.).
EOF
    fi
}

make_profiles() { # make_profiles USER
    local user=$1 pass dir
    pass=$(user_password "$user")
    dir=$CLIENTS_DIR/$user
    install -d -m 700 "$CLIENTS_DIR" "$dir"
    rm -f "$dir"/*
    if [[ $IKEV2_CERT_MODE == selfsigned ]]; then
        install -m 600 "$CA_CERT" "$dir/ikev2-vpn-ca.crt"
    fi
    write_mobileconfig "$user" "$pass" "$dir/$user.mobileconfig"
    write_sswan "$user" "$dir/$user.sswan"
    write_ps1 "$user" "$dir/$user-windows.ps1"
    write_client_readme "$user" "$pass" "$dir/README.txt"
    chmod 600 "$dir"/*
}

print_user_summary() { # print_user_summary USER
    local user=$1
    cat <<EOF

  Логин:    ${C_BLD}$user${C_RST}
  Пароль:   ${C_BLD}$(user_password "$user")${C_RST}
  Профили:  $CLIENTS_DIR/$user/
EOF
}

# --- Команды ---------------------------------------------------------------
cmd_install() {
    local opt_host="" opt_mode="" opt_email="" opt_user="" opt_pass="" opt_dns=""
    local opt_pool="" opt_ipv6=""
    while (($#)); do
        case $1 in
            --host) opt_host=${2:?--host требует значение}; shift ;;
            --host=*) opt_host=${1#*=} ;;
            --letsencrypt | --lets-encrypt) opt_mode=letsencrypt ;;
            --self-signed | --selfsigned) opt_mode=selfsigned ;;
            --email) opt_email=${2:?--email требует значение}; shift ;;
            --email=*) opt_email=${1#*=} ;;
            --user) opt_user=${2:?--user требует значение}; shift ;;
            --user=*) opt_user=${1#*=} ;;
            --password) opt_pass=${2:?--password требует значение}; shift ;;
            --password=*) opt_pass=${1#*=} ;;
            --dns) opt_dns=${2:?--dns требует значение}; shift ;;
            --dns=*) opt_dns=${1#*=} ;;
            --pool) opt_pool=${2:?--pool требует значение}; shift ;;
            --pool=*) opt_pool=${1#*=} ;;
            --ipv6) opt_ipv6=yes ;;
            --no-ipv6) opt_ipv6=no ;;
            -y | --yes) ;; # оставлено для совместимости: вопросов больше нет
            -h | --help) usage; exit 0 ;;
            *) die "Неизвестный параметр: $1 (см. --help)" ;;
        esac
        shift
    done

    require_root
    check_os

    # Значения по умолчанию — из предыдущей установки, если она была.
    IKEV2_HOST="" IKEV2_CERT_MODE="" IKEV2_LE_EMAIL="" IKEV2_POOL4="" IKEV2_POOL6="" IKEV2_DNS=""
    load_state || true
    local reinstall=0
    [[ -n $IKEV2_HOST ]] && reinstall=1

    # --- Параметры ---
    [[ -n $opt_pool ]] && IKEV2_POOL4=$opt_pool
    IKEV2_POOL4=${IKEV2_POOL4:-10.10.10.0/24}
    is_private_cidr4 "$IKEV2_POOL4" ||
        die "Неверная подсеть --pool: $IKEV2_POOL4 (нужна частная IPv4-сеть с маской /16–/29)"

    if [[ -n $opt_dns ]]; then
        IKEV2_DNS=${opt_dns// /}
    fi
    IKEV2_DNS=${IKEV2_DNS:-1.1.1.1,1.0.0.1}
    local d dns_list
    IFS=, read -r -a dns_list <<<"$IKEV2_DNS"
    ((${#dns_list[@]})) || die "Пустой список --dns"
    for d in "${dns_list[@]}"; do
        is_ipv4 "$d" || is_ipv6 "$d" || die "Неверный адрес DNS: '$d'"
    done

    if [[ $opt_ipv6 == no ]]; then
        IKEV2_POOL6=""
    elif [[ $opt_ipv6 == yes ]] || { [[ $reinstall == 0 ]] && server_has_ipv6; }; then
        [[ -n $IKEV2_POOL6 ]] || IKEV2_POOL6=$(gen_ula_pool)
    fi

    if [[ -n $opt_host ]]; then
        IKEV2_HOST=$opt_host
    elif [[ -z $IKEV2_HOST ]]; then
        info "Определение публичного IP-адреса сервера"
        IKEV2_HOST=$(detect_public_ip)
    fi
    IKEV2_HOST=${IKEV2_HOST,,}
    [[ -n $IKEV2_HOST ]] || die "Не удалось определить адрес сервера, укажите --host"
    is_ipv4 "$IKEV2_HOST" || is_fqdn "$IKEV2_HOST" ||
        die "Неверный адрес сервера: '$IKEV2_HOST' (нужен домен или IPv4)"

    if [[ -n $opt_mode ]]; then
        IKEV2_CERT_MODE=$opt_mode
    elif [[ -z $IKEV2_CERT_MODE ]]; then
        IKEV2_CERT_MODE=selfsigned
    fi
    if [[ $IKEV2_CERT_MODE == letsencrypt ]]; then
        is_fqdn "$IKEV2_HOST" || die "Для Let's Encrypt нужен домен, а не IP-адрес (--host vpn.example.com) или используйте --self-signed"
        [[ -n $opt_email ]] && IKEV2_LE_EMAIL=$opt_email
        local resolved public_ip
        resolved=$(getent ahostsv4 "$IKEV2_HOST" 2>/dev/null | awk 'NR == 1 { print $1 }') || resolved=
        [[ -n $resolved ]] || die "Домен $IKEV2_HOST не резолвится в IPv4-адрес."
        public_ip=$(detect_public_ip)
        if [[ -n $public_ip && $resolved != "$public_ip" ]]; then
            warn "$IKEV2_HOST указывает на $resolved, а публичный IP сервера — $public_ip."
            warn "Если A-запись не указывает на этот сервер, Let's Encrypt не выдаст сертификат."
        fi
    fi

    # Первый пользователь.
    local first_user="" first_pass=""
    if [[ -n $opt_user ]]; then
        first_user=$opt_user
    elif [[ -z $(list_user_names) ]]; then
        first_user=vpnuser
    fi
    if [[ -n $first_user ]]; then
        valid_username "$first_user" ||
            die "Недопустимое имя пользователя: '$first_user' (латиница, цифры, . _ @ -)"
        if [[ -n $opt_pass ]]; then
            valid_password "$opt_pass" ||
                die "Пароль: 8–128 печатных ASCII-символов, без \" и \\"
            first_pass=$opt_pass
        elif ! user_exists "$first_user"; then
            first_pass=$(gen_password)
        fi
    fi

    echo
    info "Параметры установки:"
    cat <<EOF
    Адрес сервера:  $IKEV2_HOST
    Сертификат:     $([[ $IKEV2_CERT_MODE == letsencrypt ]] && echo "Let's Encrypt" || echo "собственный CA")
    Подсеть IPv4:   $IKEV2_POOL4
    Подсеть IPv6:   ${IKEV2_POOL6:-выключено}
    DNS клиентов:   $IKEV2_DNS
EOF
    [[ -n $first_user ]] && echo "    Пользователь:   $first_user"
    echo

    # --- Установка ---
    info "Установка пакетов strongSwan"
    apt_install "${PACKAGES[@]}"
    write_strongswan_conf
    check_conflicts
    check_pool_overlap

    info "Настройка ядра (sysctl)"
    write_sysctl

    info "Настройка файрвола"
    apply_firewall

    if [[ $IKEV2_CERT_MODE == letsencrypt ]]; then
        issue_letsencrypt_cert
    else
        issue_selfsigned_server_cert
        rm -f "$LE_HOOK"
    fi

    info "Настройка strongSwan"
    if [[ -n $first_user && -n $first_pass ]]; then
        db_set_user "$first_user" "$first_pass"
    fi
    [[ -f $USERS_DB ]] || install -m 600 /dev/null "$USERS_DB"
    write_swanctl_conf
    write_secrets
    save_state

    systemctl enable strongswan.service >/dev/null 2>&1
    if ! systemctl restart strongswan.service; then
        journalctl -u strongswan.service -n 30 --no-pager >&2 || true
        die "strongSwan не запустился, см. журнал выше."
    fi
    [[ $(swanctl --list-conns 2>/dev/null) == *"$CONN_NAME: IKEv2"* ]] ||
        die "Конфигурация $CONN_NAME не загрузилась: проверьте 'journalctl -u strongswan'."

    # Копия скрипта для последующего управления.
    local self mgmt=ikev2-vpn
    self=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null) || self=
    if [[ -f $self && $self != "$SELF_BIN" ]]; then
        install -m 755 "$self" "$SELF_BIN"
    fi
    [[ -x $SELF_BIN ]] || mgmt="bash ikev2-setup.sh"

    info "Создание клиентских профилей"
    local u
    while read -r u; do
        [[ -n $u ]] && make_profiles "$u"
    done < <(list_user_names)

    echo
    printf '%s%s%s\n' "$C_GRN$C_BLD" "IKEv2 VPN-сервер готов!" "$C_RST"
    echo "  Сервер:   $IKEV2_HOST"
    if [[ -n $first_user ]]; then
        print_user_summary "$first_user"
    else
        echo "  Пользователи: $(list_user_names | paste -sd, -)"
        echo "  Профили:      $CLIENTS_DIR/"
    fi
    cat <<EOF

  В каталоге профилей: .mobileconfig (iOS/macOS), .sswan (Android, приложение
  strongSwan), -windows.ps1 (Windows 10/11) и README.txt с инструкциями.
  Скачать на компьютер:  scp -r root@$IKEV2_HOST:$CLIENTS_DIR/ .

  Управление:  $mgmt add-user ИМЯ | del-user ИМЯ | passwd ИМЯ | list-users | status

  ${C_YEL}Если у хостинга есть внешний файрвол (security group), откройте в нём
  UDP 500 и UDP 4500${C_RST}$([[ $IKEV2_CERT_MODE == letsencrypt ]] && echo "${C_YEL}, а также TCP 80 для продления сертификата${C_RST}").
EOF
}

cmd_add_user() {
    local user=${1:-} pass=${2:-}
    [[ -n $user ]] || die "Использование: $0 add-user ИМЯ [ПАРОЛЬ]"
    require_root
    require_installed
    valid_username "$user" || die "Недопустимое имя: '$user' (латиница, цифры, . _ @ -)"
    user_exists "$user" && die "Пользователь '$user' уже существует (сменить пароль: passwd)"
    if [[ -n $pass ]]; then
        valid_password "$pass" || die "Пароль: 8–128 печатных ASCII-символов, без \" и \\"
    else
        pass=$(gen_password)
    fi
    db_set_user "$user" "$pass"
    reload_creds
    make_profiles "$user"
    info "Пользователь $user добавлен"
    print_user_summary "$user"
}

cmd_passwd() {
    local user=${1:-} pass=${2:-}
    [[ -n $user ]] || die "Использование: $0 passwd ИМЯ [ПАРОЛЬ]"
    require_root
    require_installed
    user_exists "$user" || die "Пользователь '$user' не найден"
    if [[ -n $pass ]]; then
        valid_password "$pass" || die "Пароль: 8–128 печатных ASCII-символов, без \" и \\"
    else
        pass=$(gen_password)
    fi
    db_set_user "$user" "$pass"
    reload_creds
    terminate_user_sessions "$user"
    make_profiles "$user"
    info "Пароль пользователя $user изменён, активные подключения разорваны"
    print_user_summary "$user"
}

cmd_del_user() {
    local user=${1:-}
    [[ -n $user ]] || die "Использование: $0 del-user ИМЯ"
    require_root
    require_installed
    user_exists "$user" || die "Пользователь '$user' не найден"
    db_del_user "$user"
    reload_creds
    terminate_user_sessions "$user"
    rm -rf "${CLIENTS_DIR:?}/$user"
    info "Пользователь $user удалён"
}

cmd_list_users() {
    require_root
    require_installed
    local u online
    online=$(swanctl --list-sas 2>/dev/null | sed -n "s/^  remote .* EAP: '\([^']*\)'.*/\1/p" | sort -u || true)
    while read -r u; do
        [[ -n $u ]] || continue
        if grep -qxF -- "$u" <<<"$online"; then
            printf '%s  %s(в сети)%s\n' "$u" "$C_GRN" "$C_RST"
        else
            printf '%s\n' "$u"
        fi
    done < <(list_user_names)
}

cmd_profiles() {
    local user=${1:-} u
    require_root
    require_installed
    if [[ -n $user ]]; then
        user_exists "$user" || die "Пользователь '$user' не найден"
        make_profiles "$user"
        info "Профили: $CLIENTS_DIR/$user/"
    else
        while read -r u; do
            [[ -n $u ]] && make_profiles "$u"
        done < <(list_user_names)
        info "Профили: $CLIENTS_DIR/"
    fi
}

cmd_status() {
    require_root
    require_installed
    local s
    for s in strongswan.service ikev2-vpn-firewall.service; do
        printf '%-28s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"
    done
    echo "Сервер: $IKEV2_HOST   сертификат: $IKEV2_CERT_MODE   подсеть: $IKEV2_POOL4${IKEV2_POOL6:+, $IKEV2_POOL6}"
    if [[ -f $SERVER_CERT ]]; then
        echo "Сертификат сервера действует до: $(openssl x509 -in "$SERVER_CERT" -noout -enddate | cut -d= -f2)"
    fi
    echo
    strongswan_active || return 0
    echo "Активные подключения:"
    echo "  Пользователь         IP в VPN         Адрес клиента              Подключён"
    swanctl --list-sas 2>/dev/null | awk '
        /^[^ ].*: #[0-9]+,/ { if (user != "") out(); user = ""; addr = ""; vip = ""; since = "" }
        /^  remote / {
            line = $0
            if (match(line, /@ [^[]+/)) addr = substr(line, RSTART + 2, RLENGTH - 2)
            if (match(line, /EAP: \x27[^\x27]*\x27/)) user = substr(line, RSTART + 6, RLENGTH - 7)
            if (match(line, /\[[0-9a-fA-F.:]+\]$/)) vip = substr(line, RSTART + 1, RLENGTH - 2)
        }
        /^  established / { since = $2 " " $3 }
        function out() { printf "  %-20s %-16s %-26s %s\n", user, vip, addr, since; n++ }
        END { if (user != "") out(); if (!n) print "  нет" }
    '
}

cmd_uninstall() {
    local purge=0
    while (($#)); do
        case $1 in
            --purge) purge=1 ;;
            -y | --yes) ;; # оставлено для совместимости
            *) die "Неизвестный параметр: $1" ;;
        esac
        shift
    done
    require_root
    IKEV2_CERT_MODE=""
    load_state || true

    warn "Удаляются настройки VPN, CA, пользователи и профили в $CLIENTS_DIR."

    info "Остановка служб"
    systemctl disable --now ikev2-vpn-firewall.service >/dev/null 2>&1 || true
    if [[ -x $FW_SCRIPT ]]; then
        "$FW_SCRIPT" stop || true
    fi
    rm -f "$FW_UNIT" "$FW_SCRIPT"
    systemctl daemon-reload

    info "Удаление конфигурации"
    rm -f "$CONN_CONF" "$SECRETS_CONF" "$CA_CERT" "$SERVER_CERT" "$SERVER_KEY" \
        "$SWANCTL_DIR"/x509ca/ikev2-vpn-le-*.pem "$SYSCTL_CONF" "$LE_HOOK" "$STRONGSWAN_CONF"
    if [[ $IKEV2_CERT_MODE == letsencrypt ]] && command -v certbot >/dev/null; then
        certbot delete --non-interactive --cert-name "$LE_NAME" >/dev/null 2>&1 || true
    fi
    rm -rf "$STATE_DIR" "$CLIENTS_DIR"

    if ((purge)); then
        info "Удаление пакетов strongSwan"
        systemctl disable --now strongswan.service >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -q charon-systemd strongswan-swanctl \
            strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins \
            libstrongswan-standard-plugins >/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y -q >/dev/null || true
    elif systemctl is-active --quiet strongswan.service; then
        swanctl --terminate --ike "$CONN_NAME" --force >/dev/null 2>&1 || true
        systemctl restart strongswan.service || true
    fi

    rm -f "$SELF_BIN"
    info "IKEv2 VPN удалён. net.ipv4.ip_forward вернётся к исходному значению после перезагрузки."
}

main() {
    local cmd=install
    case ${1:-} in
        -h | --help) usage; return ;;
        --version) echo "$SCRIPT_VERSION"; return ;;
    esac
    if (($#)) && [[ $1 != -* ]]; then
        cmd=$1
        shift
    fi
    case $cmd in
        install) cmd_install "$@" ;;
        add-user | adduser) cmd_add_user "$@" ;;
        del-user | deluser | remove-user) cmd_del_user "$@" ;;
        passwd | password) cmd_passwd "$@" ;;
        list-users | users) cmd_list_users ;;
        profiles) cmd_profiles "$@" ;;
        status) cmd_status ;;
        uninstall) cmd_uninstall "$@" ;;
        help | -h | --help) usage ;;
        version | --version) echo "$SCRIPT_VERSION" ;;
        *) die "Неизвестная команда: $cmd (см. --help)" ;;
    esac
}

main "$@"
