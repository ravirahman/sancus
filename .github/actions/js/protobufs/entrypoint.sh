#!/bin/bash
set -ex

cd protobufs
make js_pb PROTOC_GEN_TS=$(which protoc-gen-ts) -j4
