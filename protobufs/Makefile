PROTOC := protoc
PYTHON := python3
PROTO_FOLDER := ./protobufs
NPM := npm

PYTHON_OUT := ./python
JS_OUT := ./js
PROTOC_GEN_TS := $(JS_OUT)/protobufs/node_modules/.bin/protoc-gen-ts

PROTO_FILES=$(wildcard $(PROTO_FOLDER)/*.proto) $(wildcard $(PROTO_FOLDER)/institution/*.proto) $(wildcard $(PROTO_FOLDER)/validator/*.proto)

PYTHON_PB2_FILES=$(patsubst %.proto,$(PYTHON_OUT)/%_pb2.py,$(PROTO_FILES))
PYTHON_PB2_GRPC_FILES=$(patsubst %.proto,$(PYTHON_OUT)/%_pb2_grpc.py,$(PROTO_FILES))
PYTHON_PB2_PYI_FILES=$(patsubst %.proto,$(PYTHON_OUT)/%_pb2.pyi,$(PROTO_FILES))
PYTHON_PB2_GRPC_PYI_FILES=$(patsubst %.proto,$(PYTHON_OUT)/%_pb2_grpc.pyi,$(PROTO_FILES))

JS_PB_FILES=$(patsubst %.proto,$(JS_OUT)/%_pb.js,$(PROTO_FILES))
TS_PB_D_FILES=$(patsubst %.proto,$(JS_OUT)/%_pb.d.ts,$(PROTO_FILES))
JS_SERVICE_PB_FILES=$(patsubst %.proto,$(JS_OUT)/%_pb_service.js,$(PROTO_FILES))
TS_PB_SERVICE_D_FILES=$(patsubst %.proto,$(JS_OUT)/%_pb_service.d.ts,$(PROTO_FILES))

ALL_PYTHON_FILES=$(PYTHON_PB2_FILES) $(PYTHON_PB2_GRPC_FILES) $(PYTHON_PB2_PYI_FILES) $(PYTHON_PB2_GRPC_PYI_FILES)
ALL_JS_FILES=$(JS_PB_FILES) $(TS_PB_D_FILES) $(JS_SERVICE_PB_FILES) $(TS_PB_SERVICE_D_FILES)
ALL_OUTPUT_FILES=$(ALL_PYTHON_FILES) $(ALL_JS_FILES)

.PHONY: default
default: all install

.PHONY: all
all: $(ALL_OUTPUT_FILES)

.PHONY: python_pb
python_pb: $(ALL_PYTHON_FILES)

.PHONY: js_pb
js_pb: $(ALL_JS_FILES)

.PHONY: setup
setup:
	apt-get update
	apt install -y protobuf-compiler python3-dev libssl-dev
	wget -O /usr/local/bin/protoc-gen-grpc-web https://github.com/grpc/grpc-web/releases/download/1.2.1/protoc-gen-grpc-web-1.2.1-linux-x86_64
	chmod 775 /usr/local/bin/protoc-gen-grpc-web

.PHONY: install
install:
	$(PYTHON) -m pip install -e ./python
	cd ../client && yarn install --check-files --force

.PHONY: requirements
requirements:
	$(PYTHON) -m pip install -r $(PYTHON_OUT)/requirements.lock
	$(PYTHON) -m pip install -r $(PYTHON_OUT)/requirements.txt
	cd $(JS_OUT)/protobufs && npm install

.PHONY: clean
clean:
	find $(PYTHON_OUT) -type f -name '*_pb2.py' -delete
	find $(PYTHON_OUT) -type f -name '*_pb2.pyi' -delete
	find $(PYTHON_OUT) -type f -name '*_pb2_grpc.py' -delete
	find $(JS_OUT) \( -type d -name node_modules -prune \) -o -type f -name '*_pb.js' -exec rm {} +
	find $(JS_OUT) \( -type d -name node_modules -prune \) -o -type f -name '*_pb.d.ts' -exec rm {} +
	find $(JS_OUT) \( -type d -name node_modules -prune \) -o -type f -name '*_pb_service.js' -exec rm {} +
	find $(JS_OUT) \( -type d -name node_modules -prune \) -o -type f -name '*_pb_service.d.ts' -exec rm {} +

$(PYTHON_OUT)/%_pb2.py: %.proto
	$(PROTOC) -I. --python_out $(PYTHON_OUT) $<

$(PYTHON_OUT)/%_pb2_grpc.py: %.proto
	$(PYTHON) -m grpc_tools.protoc -I. --grpc_python_out $(PYTHON_OUT) $<

$(PYTHON_OUT)/%_pb2.pyi: %.proto
	$(PROTOC) -I. --mypy_out=$(PYTHON_OUT) $<

$(PYTHON_OUT)/%_pb2_grpc.pyi: %.proto
	$(PROTOC) -I. --mypy_grpc_out=$(PYTHON_OUT) $<


$(JS_OUT)/%_pb.js: %.proto
	$(PROTOC) --js_out=import_style=commonjs,binary:$(JS_OUT) -I=. $<

$(JS_OUT)/%_pb.d.ts: %.proto
	$(PROTOC) --plugin=protoc-gen-ts=$(PROTOC_GEN_TS) --ts_out=service=grpc-web:$(JS_OUT) -I=. $<

$(JS_OUT)/%_pb_service.js: %.proto $(JS_OUT)/%_pb.d.ts
	$(PROTOC) --plugin=protoc-gen-ts=$(PROTOC_GEN_TS) --ts_out=service=grpc-web:$(JS_OUT) -I=. $<

$(JS_OUT)/%_pb_service.d.ts: %.proto $(JS_OUT)/%_pb_service.js
	$(PROTOC) --plugin=protoc-gen-ts=$(PROTOC_GEN_TS) --ts_out=service=grpc-web:$(JS_OUT) -I=. $<
