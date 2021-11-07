FROM ruimarinho/bitcoin-core:latest

RUN mkdir -p /data

COPY bitcoin.conf /data/bitcoin.conf

COPY entrypoint.sh /my_entrypoint.sh

ENTRYPOINT [ "/my_entrypoint.sh" ]

CMD [ "bitcoind" ]
