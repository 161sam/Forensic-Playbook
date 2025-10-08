.PHONY: module-matrix lint test

module-matrix:
python tools/generate_module_matrix.py

lint:
ruff check .
black --check .

test:
pytest -q --maxfail=1 --disable-warnings --cov=forensic --cov-report=term --cov-report=xml
