#!/bin/bash
# Owned ephemeral probe only. Never AUTH, MAIL, RCPT, DATA or provider credentials.
set -eu -o pipefail
exec 2>/dev/null
stage=identity
trap 'printf "mail_gateway_preflight_failed stage=%s\n" "$stage"' ERR
[ "$#" -eq 0 ]
[ "$(id -u)" = 10001 ]
stage=routes
if awk '$2=="00000000" {found=1} END {exit !found}' /proc/net/route; then false; fi
if awk '$1=="00000000000000000000000000000000" && $2=="00" && $NF!="lo" {found=1} END {exit !found}' /proc/net/ipv6_route; then false; fi
stage=direct_denial
if timeout 2 bash -c 'exec 3<>/dev/tcp/167.233.253.175/587' >/dev/null 2>&1; then false; fi
if timeout 2 bash -c 'exec 3<>/dev/tcp/167.233.253.175/443' >/dev/null 2>&1; then false; fi
if timeout 2 bash -c 'exec 3<>/dev/tcp/168.119.120.255/443' >/dev/null 2>&1; then false; fi
stage=alias
alias_ip=$(getent ahostsv4 mail.cl8y.com | awk 'NR==1 {print $1}')
case "$alias_ip" in 10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) ;; *) false;; esac
stage=tls
result=$(printf 'QUIT\r\n' | timeout 12 openssl s_client -starttls smtp -connect mail.cl8y.com:1587 -servername mail.cl8y.com -verify_hostname mail.cl8y.com -verify_return_error -brief 2>&1)
[[ "$result" == *'Verification: OK'* ]]
[[ "$result" == *'CONNECTION ESTABLISHED'* ]]
printf '%s\n' 'mail_gateway_preflight_pass uid=10001 no_default_route=true alias_private=true hostname_verified=true direct_mailu_denied=true other_targets_denied=true auth=false sends=0'
