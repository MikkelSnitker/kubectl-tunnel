#!/bin/sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
./server --network $TUNNEL_NETWORK --port $TUNNEL_PORT
