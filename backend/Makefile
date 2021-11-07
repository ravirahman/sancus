PYTHON := python3

MODULES := backend tests auditgen

TEST_ARGS := discover

.PHONY: sanitize
sanitize: isort format typecheck pylint

.PHONY: requirements
requirements:
	$(PYTHON) -m pip install -r requirements.lock
	$(PYTHON) -m pip install -r requirements.txt

.PHONY: test
test:
	$(PYTHON) -m coverage run -m unittest $(TEST_ARGS)

.PHONY: coverage
coverage:
	$(PYTHON) -m coverage xml
	$(PYTHON) -m coverage report -m

.PHONY: format
format:
	$(PYTHON) -m black -l 120 $(MODULES)

.PHONY: typecheck
typecheck:
	$(PYTHON) -m mypy .

.PHONY: pylint
pylint:
	$(PYTHON) -m pylint $(MODULES)

.PHONY: isort
isort:
	$(PYTHON) -m isort --profile black -m 3 .
