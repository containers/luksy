GO = go
BATS = bats

all: lukstool

lukstool: cmd/lukstool/*.go *.go
	$(GO) build -o lukstool ./cmd/lukstool

clean:
	$(RM) lukstool lukstool.test

test:
	$(GO) test
	$(BATS) ./tests
