.PHONY: lint test collections

# ansible.cfg points at a gitignored .vault-pass; fall back to a dummy in fresh checkouts.
ifeq ($(wildcard .vault-pass),)
export ANSIBLE_VAULT_PASSWORD_FILE := tests/fixtures/vault-pass
endif

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
