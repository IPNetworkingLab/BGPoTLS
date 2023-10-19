#!/bin/bash

if [ "$#" != "7" ]; then
    echo "This script should exactly take 7 arguments"
    echo "$0 <gobgp_bin> <gobgpd_bin> <gobgpd_cfg> <mrt_dump> <ipv4_nh> <ipv6_nh> <iface>"
    echo "    <gobgp_bin>: location of gobgp bin"
    echo "    <gobgpd_bin>: location of gobgpd_bin"
    echo "    <gobgpd_cfg>: location of gobgp config file"
    echo "    <mrt_dump>: routing table in mrt format"
    echo "    <ipv4_nh>: override IPv4 NextHop of route sent by GoBGP"
    echo "    <ipv6_nh>: override IPv6 NextHop of route sent by GoBGP"
    echo "    <iface>: Interface name facing the other BGP peer"
    exit 1
fi

# exit when any command fails
set -e

GOBGP="$1"
GOBGPD="$2"
GOBGPD_CFG="$3"
MRT_DUMP="$4"
IPv4_NH="$5"
IPv6_NH="$6"
iface="$7"

# Keep all IPv6 addresses on an interface down event.
sysctl -w net.ipv6.conf.all.keep_addr_on_down=1

echo "[INFO] Setting ${iface} down while mrt is loaded"
ip link set dev "${iface}" down

# launch gobgpd on the node
$GOBGPD --cpus=6 -f "$GOBGPD_CFG" &

# make sure gobgpd is launched and ready
sleep 1

# Start injecting Routing Table from MRT dump
$GOBGP mrt inject global --only-best --nexthop "$IPv4_NH" --no-ipv6 "$MRT_DUMP"
$GOBGP mrt inject global --only-best --nexthop "$IPv6_NH" --no-ipv4 "$MRT_DUMP"

echo "[INFO] MRT injection is finished, re-enabling ${iface}"
ip link set dev "${iface}" up
