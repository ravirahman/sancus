FROM node:buster

ENV DEBIAN_FRONTENT=noninteractive

RUN apt-get update && \
    apt-get install -y curl protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L -o /usr/local/bin/protoc-gen-grpc-web https://github.com/grpc/grpc-web/releases/download/1.2.1/protoc-gen-grpc-web-1.2.1-linux-x86_64 && \
	chmod 775 /usr/local/bin/protoc-gen-grpc-web

RUN npm install -g ts-protoc-gen

ENV DEBIAN_FRONTENT=

COPY "entrypoint.sh" "entrypoint.sh"

ENTRYPOINT [ "/entrypoint.sh" ]
