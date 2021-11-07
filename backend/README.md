# Backend

The backend provides a gRPC server for a Sancus institution. It also includes [grpcwebproxy][grpcwebproxy] which
exposes gRPC over HTTP 1.1 for web browsers.

## Getting started
1. Complete the setup instructions for [Sancus](../README.md) if you haven't already
1. Activate your Python virtual environment for Sancus
1. Setup grpcwebproxy:
   1. Download and extract the [grpcwebproxy][grpcwebproxy-download] for your operating system.
   1. Copy it into your path (e.g. `sudo cp grpcwebproxy /usr/local/bin/`)
   1. Mark it as executable (e.g. `chmod u+x /usr/local/bin/grpcwebproxy`)
1. Start the Sacnus infra if it isn't already running: `cd ../infra && docker-compose up -d`
1. `make requirements`
1. Make your changes
1. `make test` and fix any failing test cases
1. `make format && make pylint && make typecheck` and fix the errors until none appear

## How to use
`cd .. && python3 sancus.py backend`

The backend will now be running on tcp://localhost:50051 (for gRPC) and https://localhost:8443 (for gRPC over grpcwebproxy)

[grpcwebproxy]: https://github.com/improbable-eng/grpc-web/tree/master/go/grpcwebproxy
[grpcwebproxy-download]: https://github.com/improbable-eng/grpc-web/releases

## Running the backend on openstack
1. SSH into openstack: `ssh -i sancus-openstack.key ubuntu@sancus.csail.mit.edu`
1. Check backend status: `systemctl status sancus-backend.service` and check logs: `journalctl -u sancus-backend.service -f --since "1 minute ago"`
1. If the script is still running, stop it: `sudo systemctl stop sancus-backend.service`
1. Clear the backend database: `sudo mysql -p` and enter the password `password`
1. `DROP DATABASE backend;` and `exit`
1. Make desired changes to backend
1. Edit `sancus.py` to have the values in `eth.env` and `eth_contracts.env` in `infra/outputs` of `sancus-chain.csail.mit.edu`
1. Run the backend again: `sudo systemctl start sancus-backend.service`

Check backend status: `journalctl -u sancus-backend.service -f --since "1 hour ago"`

This hosts the backend at https://sancus.csail.mit.edu:18443 for gRPC calls. To see the nginx confirmation: check `/etc/nginx/sites-enabled/sancus.csail.mit.edu.conf`

Note: Because this is hosted on a different server than infra, the dotenv imports will not work, and will have to be commented out and replaced by manually copying over the account ids from `/sancus/infra/outputs` on the infra server. Also, http://localhost:8545 has to be replaced with http://sancus:dolos@sancus-chain.csail.mit.edu and http://bitcoin:password@localhost:18444" with http://bitcoin:password@sancus-chain.csail.mit.edu:58444".


