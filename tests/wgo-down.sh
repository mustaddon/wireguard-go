#!/bin/bash

if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

ip -4 rule delete table 51820
ip -4 rule delete table main suppress_prefixlength 0
ip -6 rule delete table 51820
ip -6 rule delete table main suppress_prefixlength 0
ip link delete dev wgo1
