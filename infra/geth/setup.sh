#!/bin/sh
set -ex

KEY_PASSWORD="password"
GETH_DATA_FOLDER=/data/geth
PASSWORD_FILE=/data/password
ACCOUNT_ADDRESS_FILE=/data/address
GENESIS_FILE=/data/genesis.json
ENV_FILE=/output/eth.env

if [ ! -f "$PASSWORD_FILE" ]; then 
    echo $KEY_PASSWORD > $PASSWORD_FILE
fi
if [ ! -f "$ACCOUNT_ADDRESS_FILE" ]; then
    ouput=$(geth --verbosity 0 account new --datadir $GETH_DATA_FOLDER --password $PASSWORD_FILE)
    account_address_with_quotes=${ouput:58:42}
    echo $account_address_with_quotes
    temp="${account_address_with_quotes%\"}"
    temp="${temp#\"}"
    echo $temp > $ACCOUNT_ADDRESS_FILE
fi

ACCOUNT_ADDRESS=$(cat $ACCOUNT_ADDRESS_FILE)
echo "ETH_MAIN_ADDRESS=$ACCOUNT_ADDRESS" > $ENV_FILE
chmod 644 $ENV_FILE

if [ ! -f "$GENESIS_FILE" ]; then
    ACCOUNT_ADDRESS_WITHOUT_PREFIX="${ACCOUNT_ADDRESS:2}"
    CONFIG=$(cat <<-END
{
    "config": {
        "chainId": 58,
        "homesteadBlock": 0,
        "eip150Block": 0,
        "eip155Block": 0,
        "eip158Block": 0,
        "byzantiumBlock": 0,
        "constantinopleBlock": 0,
        "petersburgBlock": 0,
        "istanbulBlock": 0,
        "clique": {
            "period": 3,
            "epoch": 30000
        }
    },
    "alloc": {
        "${ACCOUNT_ADDRESS}": {
            "balance": "1000000000000000000000000"
        }
    },
    "coinbase": "0x0000000000000000000000000000000000000000",
    "difficulty": "0x0",
    "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000${ACCOUNT_ADDRESS_WITHOUT_PREFIX}0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "gasLimit": "0x8FFFFF",
    "nonce": "0x0000000000000042",
    "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "timestamp": "0x00"
}
END
    )
    echo ${CONFIG} > $GENESIS_FILE
fi
cat $GENESIS_FILE
rm -rf $GETH_DATA_FOLDER/chaindata
geth init --datadir $GETH_DATA_FOLDER $GENESIS_FILE

# Run whatever we were going to run anyways
exec geth --datadir $GETH_DATA_FOLDER --mine --nousb --miner.threads '1' --miner.gasprice '0' --miner.recommit '1s' --nodiscover --fakepow \
    --syncmode "full" --gcmode "archive" --verbosity 2 \
    --allow-insecure-unlock --miner.etherbase $ACCOUNT_ADDRESS --unlock $ACCOUNT_ADDRESS --password $PASSWORD_FILE \
    --http --http.addr "0.0.0.0" --http.vhosts '*' --http.corsdomain '*' --http.api="db,eth,net,web3,personal,web3"
