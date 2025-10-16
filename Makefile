.PHONY: help install build publish clean test

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install    Install from source"
	@echo "  build      Build package"
	@echo "  publish    Publish to Artifactory"
	@echo "  clean      Clean build files"
	@echo "  test       Run tests"

install:
	pip install -e .

build:
	python -m build

publish: build
	./publish.sh

clean:
	rm -rf build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

test:
	pytest tests/ -v
