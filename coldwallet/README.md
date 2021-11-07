# Cold Wallet

The cold wallet protobuf-based CLI provides a mechanism for Sancus institutions to manage offline signing keys.

It implements the functions as defined in the [Cold Wallet protobuf](../protobufs/proto/coldwallet.proto).
Since it is a command line interface meant to be run offline, it does not use a gRPC server.

## Getting started
1. Complete the setup instructions for [Sancus](../README.md) if you haven't already
1. Activate your Python virtual environment for Sancus
1. `make requirements`
1. `make test`
1. Make your changes
1. `make test` and fix any failing test cases
1. `make format && make pylint && make typecheck` and fix the errors until none appear

## How to use
`python3 -m coldwallet.coldwallet --help`
