#!/bin/bash

if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cp "$SCRIPT_DIR/../wireguard-go" /usr/bin

wireguard-go --version
wireguard-go wgo1
timeout 1s wg setconf wgo1 /etc/wireguard/wgo1.conf
ip -4 address add 10.66.66.2/32 dev wgo1
ip -6 address add fd42:42:42::2/128 dev wgo1
ip link set mtu 1420 up dev wgo1
timeout 1s wg set wgo1 fwmark 51820
ip -6 route add ::/0 dev wgo1 table 51820
ip -6 rule add not fwmark 51820 table 51820
ip -6 rule add table main suppress_prefixlength 0
ip -4 route add 0.0.0.0/0 dev wgo1 table 51820
ip -4 rule add not fwmark 51820 table 51820
ip -4 rule add table main suppress_prefixlength 0
sysctl -q net.ipv4.conf.all.src_valid_mark=1
wg show
