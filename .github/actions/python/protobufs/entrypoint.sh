#!/bin/bash
set -ex

cd protobufs
make python_pb -j4
