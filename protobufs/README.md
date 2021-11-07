# Protobufs

Sancus uses [Google Protobufs][protobufs] and [gRPC][grpc] for data serialization and communication, respectively.
Protobufs are an attractive alternative to JSON as they are typed, highly structured, and compact. gRPC is the
transport mechanism for protobufs (similar to how HTTP REST is for JSON). Both protobufs and gRPC have native 
Python and TypeScript bindings.

## Getting started

First, please complete the setup instructions for [Sancus](../README.md).

### On macOS
1. `brew install protobuf node`
1. Download [protoc-gen-grpc-web][protoc-gen-grpc-web-mac] and move this binary to `/usr/local/bin/protoc-gen-grpc-web`
1. `sudo chmod 755 /usr/local/bin/protoc-gen-grpc-web`
1. Activate your Sancus python environment
1. `make requirements`

### On Linux/WSL
1. `sudo make setup`
1. Activate your Sancus python environment
1. `make requirements`


## Working with Protobufs

The [proto](proto/) folder contains the protocol buffer definitions used throughout Sancus.
The [js](js/) and [python](python/) folders contain the langauge-specific protobuf and gRPC code,
which can then be installed modules (similar to any other npm or pypy package).

## Building protobufs
After you modify the [proto](proto/) folder **or pull code that modified the protobufs**, it is crucial to rebuild
the protobufs and reinstall the generated modules. Otherwise, you'll be scratching your head why all the test cases
are failing. To build the protobufs.

1. Activate your Sancus python environment
1. `make clean && make`


[protobufs]: https://developers.google.com/protocol-buffers
[grpc]: https://grpc.io/
[protoc-gen-grpc-web-mac]: https://github.com/grpc/grpc-web/releases/download/1.2.1/protoc-gen-grpc-web-1.2.1-darwin-x86_64
