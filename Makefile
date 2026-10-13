PY      ?= .venv/bin/python
DATA    ?= data/security-datasets
export PYTHONPATH := src

.DEFAULT_GOAL := help
.PHONY: help install lock download lint rules-lint test evaluate first-pass convert coverage all format clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Create .venv and install the package with dev tools (versions pinned by constraints.txt)
	python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]" -c constraints.txt

lock: ## Re-pin constraints.txt to the latest versions pyproject.toml allows (needs uv)
	uv pip compile pyproject.toml --extra dev --universal --python-version 3.11 -o constraints.txt

download: ## Fetch the pinned OTRF Security-Datasets recordings (MIT), verify each git SHA
	$(PY) -m dac download -o $(DATA)

lint: ## Lint and check formatting of the Python code
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests

rules-lint: ## Validate every Sigma rule (pySigma validators + project checks)
	$(PY) -m dac lint

test: ## Run the test suite (no dataset needed: synthetic events + tiny fixtures)
	$(PY) -m pytest --cov --cov-report=term-missing

evaluate: ## Run the rules on the recordings -> detection matrix, metrics, figures
	$(PY) -m dac evaluate --data $(DATA)

first-pass: ## Rebuild the first-pass rules from reports/first_pass/rules.diff and evaluate them
	rm -rf runtime/first_pass_rules && mkdir -p runtime && cp -R rules runtime/first_pass_rules
	patch -R -p1 -s -d runtime/first_pass_rules < reports/first_pass/rules.diff
	$(PY) -m dac evaluate --data $(DATA) --rules runtime/first_pass_rules --out reports/first_pass --no-figures

convert: ## Convert every rule to Splunk SPL, Elastic Lucene and Microsoft KQL -> reports/queries
	$(PY) -m dac convert -o reports/queries

coverage: ## Write the ATT&CK Navigator coverage layer -> reports/attack_navigator_layer.json
	$(PY) -m dac coverage -o reports/attack_navigator_layer.json

all: rules-lint evaluate convert coverage ## Lint rules, evaluate, convert and build the coverage layer

format: ## Auto-format the code
	$(PY) -m ruff check --fix src tests
	$(PY) -m ruff format src tests

clean: ## Remove caches and generated run output (keeps data/ and committed reports)
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov reports/queries
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
