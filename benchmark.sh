#!/bin/bash

if [ "$(whoami)" != "root" ]; then
    echo "Please run me as root"
    exit 1;
fi

docker run --rm --detach --interactive --tty --name server --env I_AM_SERVER=server openssl-csidh

LATENCIES="0 0.5 1 2 3 4 5 10 15 20 25 30 40 50 60 70 80 90 100 120 140 160 180 200 250 300 350 400"

# figure out interface
INTERFACE=$(./dockerveth.sh | cut -f2)
SERVERIP=$(docker container inspect server | jq -r ".[0].NetworkSettings.IPAddress")

# Output directory
DIR=measurements

quit() {
    echo "Stopping"
    echo "Terminating server container"
    docker kill server
    exit $1
}

mkdir -p "${DIR}"

echo "Name of the server interface: $INTERFACE"
echo "IP address of the server: $SERVERIP"

for lat in $LATENCIES; do
    echo "Setting up measurements for $lat ms"
    tc qdisc add dev $INTERFACE root netem delay ${lat}ms || quit 1

    echo "Setting up monitoring"
    tcpdump --time-stamp-precision nano -i $INTERFACE -w ${DIR}/measurement-$(date +%s)-${lat}ms.pcap &
    sleep 3

    echo "Run measurements"
    docker run --rm --interactive --tty --name client --env SERVERIP=$SERVERIP openssl-csidh || quit 1

    echo "Stopping monitoring"
    killall -INT tcpdump || quit 1
    sleep 3

    echo "Checking if tcpdump quit."
    pgrep tcpdump && quit 1 || true

    echo "Removing latency"
    tc qdisc del dev $INTERFACE root netem delay ${lat}ms || quit 1
    sleep 2
done

echo "Done!"

quit 0

