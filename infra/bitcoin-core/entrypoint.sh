#!/bin/bash
set -ex

DATADIR=/data
WALLET_FILE="$DATADIR/regtest/wallets/wallet.dat"

mkdir -p $DATADIR

if [ ! -f "$WALLET_FILE" ]; then
    bitcoin-wallet -datadir=$DATADIR -wallet=$WALLET_FILE -chain=regtest create 
fi

exec /entrypoint.sh "$@"
