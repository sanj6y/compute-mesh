# compute-mesh — Local Compute Mesh
#
# Generated protobuf code is checked in so `go build ./...` works without protoc.
# Re-run `make proto` after editing anything under proto/. CI regenerates with
# protoc 34.x and fails on drift (the protoc version header line is ignored).

GO        ?= go
GOBIN     := $(shell $(GO) env GOPATH)/bin
PROTOC    ?= protoc
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

PROTO_DIR  := proto
PROTO_SRCS := $(shell find $(PROTO_DIR) -name '*.proto')

.PHONY: all build test test-race lint proto proto-tools clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/meshd  ./cmd/meshd
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/meshctl ./cmd/meshctl

test:
	$(GO) test ./...

test-race:
	$(GO) test -race -count=1 ./...

lint:
	$(GO) vet ./...

# protoc plugins are pinned via go.mod (tools directive) so codegen is reproducible.
proto-tools:
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc

proto: proto-tools
	PATH="$(GOBIN):$$PATH" $(PROTOC) \
		-I $(PROTO_DIR) \
		--go_out=$(PROTO_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_SRCS)

clean:
	rm -rf bin/
