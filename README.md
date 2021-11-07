# Sancus: A trustless, privacy preserving, decentralized bank

## Code Structure
Sancus uses a monorepo!

- The [auditor](auditor/) folder contains a Python-based auditing client that validates the commitments published
    by the institution against blockchain data
- The [backend](backend/) folder contains the Python backend that a sancus institution would run
- The [client](client/) folder contains a React frontend that customers would use to interact with the backend
- The [coldwallet](coldwallet/) folder contains a Python-based command line interface that an institution can use
    to manage cold (offline) cryptographic keys
- The [common](common/) folder contains modules shared by both the backend and the auditor
- The [experiments](experiments/) folder contains a scriptable experiment runner and a set of experiments to evaluate the system
- The [infra](infra/) folder contains Docker configurations for local (private) Bitcoin, Ethereum, and IPFS nodes
- The [protobufs](protobufs/) folder contains the Protocol Buffer and gRPC service definitions for all Sancus components


## Getting Started

1. Install Python 3.8, NodeJS, and Yarn:
    1. On macOS:
        ```bash
        brew install python@3.8 nodejs openssl
        npm install --global yarn
        ```
    1. On Linux: 
        ```bash
        sudo apt-get update
        sudo apt-get install -y python3.8 libssl-dev openssl automake wget curl
        curl -sL https://deb.nodesource.com/setup_15.x | sudo -E bash -
        sudo apt-get install -y nodejs
        npm install --global yarn
        ```
1. Run `make certificates` in this folder
2. Trust these SSL certificates:
   1. In windows, add `sancus.crt` to the trusted root certificate store. See [this-article][windows-ssl]
   2. In macOS, run in a terminal: `sudo security add-trusted-cert -d -r trustAsRoot -k sancus.crt`
   3. In Firefox, add `sancus.crt` as a trusted authority. See [this-article][firefox-ssl]
3. Go to the [infra](infra/) folder and follow those setup instructions
4. Set up a Python virtual environment for Sancus: `python3 -m venv env`
5. Activate this virtual environment: `source env/bin/activate`
6. Go to the [protobufs](protobufs/) folder and follow those setup instructions
7. Go to the [backend](backend/) folder and follow those setup instructions
8. Go to the [client](client/) folder and follow those setup instructions

If everything works, you should be able to visit http://localhost:3000 and use your own, local version of Sancus

[firefox-ssl]: https://javorszky.co.uk/2019/11/06/get-firefox-to-trust-your-self-signed-certificates/
[windows-ssl]: https://support.securly.com/hc/en-us/articles/360026808753-How-do-I-manually-install-the-Securly-SSL-certificate-on-Windows
