#!/bin/bash
set -ex

bitcoin-cli -chain=regtest -rpcwait=1 -rpcport=18444 -rpcuser=bitcoin -rpcpassword=password -rpcconnect=bitcoin-core -generate 101

while true; do
    bitcoin-cli -chain=regtest -rpcwait=1 -rpcport=18444 -rpcuser=bitcoin -rpcpassword=password -rpcconnect=bitcoin-core -generate 1
    sleep 3
done
