#!/bin/bash

if (( EUID != 0 )); then
    echo "Please run as root"
    exit 1
fi

if [ "$#" -ne 1 ]; then
  echo "$0 <MRT_SAVE_DIR>"
  echo " <MRT_SAVE_DIR> directory to save mrt dumps"
  exit 1
fi

SAVE_DIR=$1

if ! test -d "$SAVE_DIR"; then
  echo "${SAVE_DIR}: directory does not exist"
  exit 1
fi


for test_type in tcp tls tcp_ao tcp_ao_tls; do
  ./test_topo.sh start_bird "$test_type"
  sleep 140
  ./test_topo.sh stop_bird
  sleep 10
  mv /tmp/test_perf/rtr1/rtr1.mrt "${SAVE_DIR}/rtr1.${test_type}.mrt"
  sync
done