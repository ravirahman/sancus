FROM python:3.8

ENV DEBIAN_FRONTENT=noninteractive

RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install mypy-protobuf grpcio-tools

ENV DEBIAN_FRONTENT=

COPY "entrypoint.sh" "entrypoint.sh"

ENTRYPOINT [ "/entrypoint.sh" ]
