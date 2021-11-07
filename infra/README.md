# Infra

This infra folder contains a private Bitcoin node, private Ethereum node, and private IPFS node as Docker containers.
Docker provides a platform-agnostic mechanism for running programs and services.


## What is provided
* An Ethereum node at `http://localhost:8545` with an unlocked wallet and prefunded account. This node
    uses [Geth Proof-of-Authority][geth-poa].
* A Bitcoin node at `http://bitcoin:password@localhost:18444` with an unlocked wallet and prefunded account.
* A script that continuously causes new Bitcoin blocks to get mined
* An IPFS node at http://localhost:8080

Note that data is persistent. Restarting the servers will keep existing Blockchain and IPFS state.
## Getting started
1. Install [Docker][docker] and [Docker Compose][docker-compose]
1. Run `sudo docker-compose up`. Leave this terminal open. To shut everything down, Ctrl-C it.
1. To remove all data and start over from scratch, run `sudo docker-compose rm -fsv`.

[docker]: https://docs.docker.com/get-docker/
[docker-compose]: https://docs.docker.com/compose/install/
[geth-poa]: https://geth.ethereum.org/docs/interface/private-network

## Steps For Running Sancus on Openstack
1. ssh into sancus-chain on openstack
`ssh -i sancus-openstack.key ubuntu@sancus.csail.mit.edu`
2. if the sancus chain is still running and you want to reset it:
`screen -R infra` and hold Ctrl+C
`sudo docker-compose down -v`
3. Run the sancus chain again: 
`sudo docker-compose up --build`
4. Exit the screen by holding Ctrl+A and then D.
5. `cat ~/sancus/infra/output/eth.env` and use those values in the backend
6. `cat ~/sancus/infra/output/eth_contracts.env` and use those values in the backend

The nginx configuration map Ethereum, Bitcoin and IPFS to the following ports on http://sancus-chain.csail.mit.edu:
- geth: 48545
- bitcoin: 58444
- IPFS: 48080

geth and IPFS are secured with HTTP basic encryption: `sancus:dolos` and bitcoin with `bitcoin:password`.

Nginx configuration file: `/etc/nginx/sites-enabled/infra_server.conf`
