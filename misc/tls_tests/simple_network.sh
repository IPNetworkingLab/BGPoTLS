#!/bin/bash

if (( EUID != 0 )); then
    echo "Please run as root"
    exit 1
fi

function usage() {
  echo "$0 {start|stop|restart}"
  exit 1
}

function start() {
    ip netns add rtr1
    ip netns add rtr2

    # add link between the two netns
    ip link add eth-rtr2 netns rtr1 type veth peer eth-rtr1 netns rtr2

    ip -n rtr1 link set dev lo up
    ip -n rtr2 link set dev lo up

    ip -n rtr1 addr add 10.21.42.1/24 dev eth-rtr2
    ip -n rtr2 addr add 10.21.42.2/24 dev eth-rtr1

    ip -n rtr1 link set dev eth-rtr2 up
    ip -n rtr2 link set dev eth-rtr1 up

    # prepare bird environment
    mkdir -p "/tmp/test_conf"
    mkdir -p "/tmp/test_conf/rtr1"
    mkdir -p "/tmp/test_conf/rtr2"

    cp rtr1* "/tmp/test_conf/rtr1"
    cp rtr2* "/tmp/test_conf/rtr2"
    cp ca.cert.pem "/tmp/test_conf"

}

function stop() {
    ip netns del rtr1
    ip netns del rtr2

    rm -rf /tmp/test_conf
}


case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  retart)
    stop && start
    ;;
  *)
    usage
    ;;
esac