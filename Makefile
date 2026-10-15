# auth-server-go — 构建与质量门禁
#
# `make check` 是委托方要求的聚合检查（等价 npm run check），退出码必须为 0。

GO   ?= go
NODE ?= node
BIN  := bin/auth-server-go

.PHONY: all build test test-race vet fmt-check check check-api-docs clean

all: check

build:
	$(GO) build -o $(BIN) ./cmd/auth-server-go

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test ./... -count=1 -race

vet:
	$(GO) vet ./...

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then echo "gofmt 未通过："; echo "$$files"; exit 1; fi; \
	echo "gofmt: OK"

check-api-docs:
	$(NODE) scripts/check-api-docs.mjs

check: fmt-check vet test check-api-docs
	@echo "check: OK"

clean:
	rm -rf bin
