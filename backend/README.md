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
