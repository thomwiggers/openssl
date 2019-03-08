#!/bin/bash

set -e

if [ "$I_AM_SERVER" = "server" ]; then 
    echo "I am a server"
    ./apps/openssl s_server -cert csidh.cert -key csidh.key -optls
else
    echo "I am a client"
    for i in $(seq 1 1000); do
        echo "Attempt $i"
        echo hi | ./apps/openssl s_client -connect $SERVERIP:4433 -optls
    done
fi

