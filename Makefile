.PHONY: test scan

test:
	python -m unittest discover -s tests -v

scan:
	python -m mcp_policy_guard scan . --fail-on critical
