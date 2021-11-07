# Auditor

The auditor provides a gRPC server to validate the commitments published by a Sancus institution

## Getting started
1. Complete the setup instructions for [Sancus](../README.md) if you haven't already
1. Activate your Python virtual environment for Sancus
1. Start the Sacnus infra if it isn't already running: `cd ../infra && docker-compose up -d`
1. `make requirements`
1. Make your changes.
1. `make test` and fix any failing test cases.
1. `make format && make pylint && make typecheck` and fix the errors until none appear
