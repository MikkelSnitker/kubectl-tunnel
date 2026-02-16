#!/bin/sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
socat -d -d TCP-LISTEN:$TUNNEL_PORT,fork TUN:$TUNNEL_NETWORK,up
