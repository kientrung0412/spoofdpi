.PHONY: build build-windows release test lint fmt fmt-check pre-commit claude

build:
	cargo build

build-windows:
	cargo build --release --target x86_64-pc-windows-gnu

release:
	cargo build --release

test:
	cargo test $(ARGS)

lint:
	cargo clippy --all-targets -- -D warnings
	cargo clippy --target x86_64-pc-windows-gnu -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

pre-commit:
	$(MAKE) test
	$(MAKE) fmt-check
	$(MAKE) lint

claude:
	mkdir -p .claude
	ln -sf ../.agents/rules .claude/rules
	ln -sf ../.agents/AGENTS.md .claude/CLAUDE.md
