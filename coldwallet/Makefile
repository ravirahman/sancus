PYTHON := python3

MODULES := coldwallet tests

TEST_ARGS := discover

.PHONY: sanitize
sanitize: isort format typecheck pylint

.PHONY: test
test:
	$(PYTHON) -m unittest $(TEST_ARGS)

.PHONY: requirements
requirements:
	$(PYTHON) -m pip install -r requirements.lock
	$(PYTHON) -m pip install -r requirements.txt

.PHONY: format
format:
	black -l 120 $(MODULES)

.PHONY: typecheck
typecheck:
	mypy .

.PHONY: pylint
pylint:
	pylint $(MODULES)

.PHONY: isort
isort:
	$(PYTHON) -m isort --profile black -m 3 .
