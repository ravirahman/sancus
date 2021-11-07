OPENSSL := openssl
PYTHON := python3

MODULES := sancus.py

.PHONY: certificates
certificates: sancus.key sancus.pem sancus.crt

.PHONY: setup
setup: certificates
# TODO copy grpc web proxy into path
# TODO install docker
	sudo apt-get update
	sudo apt-get install -y python3.8 libssl-dev openssl automake wget curl
	curl -sL https://deb.nodesource.com/setup_15.x | sudo -E bash -
	sudo apt-get install -y nodejs
	npm install --global yarn
	cd protobufs && sudo $(MAKE) setup
	cd protobufs && $(MAKE) requirements
	cd protobufs && $(MAKE)
	cd client && yarn
	$(PYTHON) -m pip install -e ./auditor
	$(PYTHON) -m pip install -e ./backend
	$(PYTHON) -m pip install -e ./common

.PHONY: clean
clean:
	rm -f sancus.key sancus.pem sancus.crt

sancus.key:
	$(OPENSSL) genrsa -out $@ 2048

sancus.pem: sancus.key
	$(OPENSSL) rsa -in $< -pubout > $@

sancus.crt: sancus.key ssl_req.conf
	$(OPENSSL) req -key $< -out $@ -x509 -config ssl_req.conf -days 10000 -extensions 'req_ext'


.PHONY: sanitize
sanitize: isort format typecheck pylint

.PHONY: format
format:
	$(PYTHON) -m black -l 120 $(MODULES)

.PHONY: typecheck
typecheck:
	$(PYTHON) -m mypy $(MODULES)

.PHONY: pylint
pylint:
	$(PYTHON) -m pylint $(MODULES)

.PHONY: isort
isort:
	$(PYTHON) -m isort --profile black -m 3 $(MODULES)

.PHONY: requirements
requirements:
	$(PYTHON) -m pip install -r requirements.txt
