GO = go
BATS = bats

all: lukstool

lukstool: cmd/lukstool/*.go *.go
	$(GO) build -o lukstool ./cmd/lukstool

check:
	$(GO) test
	$(BATS) ./tests
