.PHONY: lint test collections

SCRIPTS := $(wildcard roles/*/files/multihop-*)
PLAYBOOKS := $(wildcard playbooks/*.yml)

collections:
	uv run ansible-galaxy collection install -r requirements.yml -p ./collections

lint:
	@if [ -n "$(SCRIPTS)" ]; then shellcheck $(SCRIPTS); fi
	uv run ansible-lint
	@for p in $(PLAYBOOKS); do uv run ansible-playbook --syntax-check $$p || exit 1; done

test:
	uv run pytest tests; rc=$$?; if [ $$rc -ne 0 ] && [ $$rc -ne 5 ]; then exit $$rc; fi
	bats tests/bats
