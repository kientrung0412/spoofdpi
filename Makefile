.PHONY: build build-windows test lint fmt fmt-check pre-commit claude

build:
	go build ./cmd/...

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o spoofdpi.exe ./cmd/spoofdpi

test:
	go test $(ARGS) -race -tags network ./... -v

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

fmt-check:
	golangci-lint fmt --diff

pre-commit:
	$(MAKE) test
	$(MAKE) fmt-check
	$(MAKE) lint

claude:
	mkdir -p .claude
	ln -sf ../.agents/rules .claude/rules
	ln -sf ../.agents/AGENTS.md .claude/CLAUDE.md
