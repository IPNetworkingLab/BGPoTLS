#!/bin/bash

if (( EUID != 0 )); then
    echo "Please run as root"
    exit 1
fi

WORK_DIR=/tmp/test_perf


function usage() {
  echo "$0 {config|cold_start {tcp|tls|tcp_ao|tcp_ao_tls}|start_bird {tcp|tls|tcp_ao|tcp_ao_tls}|stop_bird|destroy}"
  echo "  config: setup Netns, temp directory, etc."
  echo "  cold_start: start gobgp, inject full routing table and launch BIRD routers"
  echo "              with the corresponding config. See start_bird arguments."
  echo "  start_bird: launch BIRD router with the corresponding config. Current configs are:"
  echo "              tcp: BGP over plain TCP"
  echo "              tls: BGP over TLS/TCP"
  echo "              tcp_ao: BGP over plain TCP with AO TCP segment authentication"
  echo "              tcp_ao_tls: BGP over TLS with TCP AO authentication"
  echo "  destroy: "
  exit 1
}

function fetch_mrt_dump() {
  if test -f "${WORK_DIR}"/gobgp/mrt.dump; then
    # dump is already present
    return
  fi

  curl -L "https://data.ris.ripe.net/rrc01/2023.11/bview.20231115.0000.gz" -o - | \
     zcat > "$WORK_DIR"/gobgp/mrt.dump
}

function config_topo() {
  ip netns add rtr1
  ip netns add rtr2
  ip netns add rtr3
  ip netns add gobgp


  ip link add eth-gobgp netns rtr1 type veth peer eth-r1 netns gobgp
  ip link add eth-r2    netns rtr1 type veth peer eth-r1 netns rtr2
  ip link add eth-r3    netns rtr1 type veth peer eth-r1 netns rtr3
  ip link add eth-r3    netns rtr2 type veth peer eth-r2 netns rtr3

  ip -n rtr1 link set dev lo up
  ip -n rtr2 link set dev lo up
  ip -n rtr3 link set dev lo up
  ip -n gobgp  link set dev lo up

  ip -n rtr1 link set dev eth-gobgp up
  ip -n rtr1 link set dev eth-r2 up
  ip -n rtr1 link set dev eth-r3 up

  ip -n rtr2 link set dev eth-r1 up
  ip -n rtr2 link set dev eth-r3 up

  ip -n rtr3 link set dev eth-r2 up
  ip -n rtr3 link set dev eth-r1 up

  ip -n gobgp link set dev eth-r1 up

  ip -n gobgp addr add 172.16.61.2/31 dev eth-r1
  ip -n gobgp addr add fc01::61:2/127 dev eth-r1
  ip -n rtr1  addr add 172.16.61.3/31 dev eth-gobgp
  ip -n rtr1  addr add fc01::61:3/127 dev eth-gobgp

  ip -n rtr1 addr add 172.16.61.4/31 dev eth-r3
  ip -n rtr1 addr add fc01::61:4/127 dev eth-r3
  ip -n rtr3 addr add 172.16.61.5/31 dev eth-r1
  ip -n rtr3 addr add fc01::61:5/127 dev eth-r1

  ip -n rtr2 addr add 172.16.61.6/31 dev eth-r3
  ip -n rtr2 addr add fc01::61:6/127 dev eth-r3
  ip -n rtr3 addr add 172.16.61.7/31 dev eth-r2
  ip -n rtr3 addr add fc01::61:7/127 dev eth-r2

  ip -n rtr1 addr add 172.16.61.8/31 dev eth-r2
  ip -n rtr1 addr add fc01::61:8/127 dev eth-r2
  ip -n rtr2 addr add 172.16.61.9/31 dev eth-r1
  ip -n rtr2 addr add fc01::61:9/127 dev eth-r1

  # setup delay/BW (1Gbps, 15ms one way delay)
  ip netns exec rtr1 ./setup_delay.sh eth-gobgp 15ms 1000Mbit 25ms
  ip netns exec rtr1 ./setup_delay.sh eth-r2 15ms 1000Mbit 25ms
  ip netns exec rtr1 ./setup_delay.sh eth-r3 15ms 1000Mbit 25ms

  ip netns exec rtr2 ./setup_delay.sh eth-r1 15ms 1000Mbit 25ms
  ip netns exec rtr2 ./setup_delay.sh eth-r3 15ms 1000Mbit 25ms

  ip netns exec rtr3 ./setup_delay.sh eth-r1 15ms 1000Mbit 25ms
  ip netns exec rtr3 ./setup_delay.sh eth-r2 15ms 1000Mbit 25ms

  ip netns exec gobgp ./setup_delay.sh eth-r1 15ms 1000Mbit 25ms

  mkdir -p "$WORK_DIR"/gobgp
  mkdir -p "$WORK_DIR"/rtr1
  mkdir -p "$WORK_DIR"/rtr2
  mkdir -p "$WORK_DIR"/rtr3

  # copy gobgp config
  cp gobgp.conf "$WORK_DIR"/gobgp

  # copy bird config
  for cfg_dir in tcp tls tcp_ao tcp_ao_tls; do
    for rtr in rtr1 rtr2 rtr3; do
      cp "$cfg_dir"_cfg/"$rtr".conf "$WORK_DIR"/"$rtr"/"$rtr"."$cfg_dir".conf
    done
  done

  # copy cert & keys
  cp certs/ca.cert.pem "$WORK_DIR"/
  cp certs/rtr1.* "$WORK_DIR"/rtr1
  cp certs/rtr2.* "$WORK_DIR"/rtr2
  cp certs/rtr3.* "$WORK_DIR"/rtr3

  fetch_mrt_dump

  echo "[INFO] You must copy bird and gobgp/gobgpd yourself (if not already done)!
        (${WORK_DIR}/bird & ${WORK_DIR}/gobgp/gobgpd)"
}


function start_gobgp() {
  ip netns exec gobgp ./gobgp.sh \
                           "$WORK_DIR"/gobgp/gobgp \
                           "$WORK_DIR"/gobgp/gobgpd \
                           "$WORK_DIR"/gobgp/gobgp.conf \
                           "$WORK_DIR"/gobgp/mrt.dump \
                           "172.16.61.2" \
                           "fc01::61:2" \
                           "eth-r1"
}

function start_bird_rtr() {
  # make sure rtr1.mrt does not exist anymore
  if test -f "$WORK_DIR"/rtr1/rtr1.mrt; then
    echo "${WORK_DIR}/rtr1/rtr1.mrt still exists. Please move it. I will not start BIRD otherwise"
    exit 1
  fi

  case "$1" in
    "tcp"|"tls"|"tcp_ao"|"tcp_ao_tls")
      SUFFIX=".${1}"
      ;;
    *)
      echo "Unsupported mode ${1}"
      usage
      ;;
  esac

  # rtr1
  ip netns exec rtr1 "$WORK_DIR"/bird \
        -fc "$WORK_DIR"/rtr1/rtr1"${SUFFIX}".conf \
        -s "$WORK_DIR"/rtr1/rtr1.sk \
        -D "$WORK_DIR"/rtr1/rtr1.stderr \
        -P "$WORK_DIR"/rtr1/rtr1.pid &
  # rtr2
  ip netns exec rtr2 "$WORK_DIR"/bird \
        -fc "$WORK_DIR"/rtr2/rtr2"${SUFFIX}".conf \
        -s "$WORK_DIR"/rtr2/rtr2.sk \
        -D "$WORK_DIR"/rtr2/rtr2.stderr \
        -P "$WORK_DIR"/rtr2/rtr2.pid &
  # rtr3
  ip netns exec rtr3 "$WORK_DIR"/bird \
        -fc "$WORK_DIR"/rtr3/rtr3"${SUFFIX}".conf \
        -s "$WORK_DIR"/rtr3/rtr3.sk \
        -D "$WORK_DIR"/rtr3/rtr3.stderr \
        -P "$WORK_DIR"/rtr3/rtr3.pid &
}


function cold_start() {
  # first start BIRD routers
  # as gobgp mrt injection takes
  # a lot of time...
  start_bird_rtr "$1"
  start_gobgp
}

function stop_gobgp() {
  pkill gobgpd
}

function stop_bird_rtr() {
  kill "$(cat "$WORK_DIR"/rtr1/rtr1.pid)"
  kill "$(cat "$WORK_DIR"/rtr2/rtr2.pid)"
  kill "$(cat "$WORK_DIR"/rtr3/rtr3.pid)"
}

function stop_all() {
  stop_gobgp
  stop_bird_rtr
}

function destroy() {
  stop_all
  ip netns del gobgp
  ip netns del rtr1
  ip netns del rtr2
  ip netns del rtr3
  rm -rf "$WORK_DIR"
}

function check_ns() {
  if ip netns exec rtr1 true > /dev/null 2>&1; then
    return 0
  else
    return 1
  fi
}


# entry point
case "$1" in
  "config")
    if check_ns; then
      echo "Already configured. Nothing to do"
    else
      config_topo
    fi
    ;;
  "cold_start")
    if ! check_ns; then
      echo "Configuring topo"
      config_topo
    fi
    cold_start "$2"
    ;;
  "start_bird")
    if check_ns; then
      start_bird_rtr "$2"
    else
      echo "Topo not configured --> cold_start $2"
      cold_start "$2"
    fi
    ;;
  "stop_bird")
    stop_bird_rtr
    ;;
  "destroy")
    destroy
    ;;
   *)
    usage
    ;;
esac
