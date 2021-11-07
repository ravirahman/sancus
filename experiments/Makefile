PYTHON := python3

MODULES := experiments utils

.PHONY: sanitize
sanitize: isort format typecheck pylint

.PHONY: requirements
requirements:
	$(PYTHON) -m pip install -r requirements.lock
	$(PYTHON) -m pip install -r requirements.txt

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
