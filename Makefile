GO = go
BATS = bats

all: luksy

luksy: cmd/luksy/*.go *.go
	$(GO) build -o luksy ./cmd/luksy

clean:
	$(RM) luksy luksy.test

test:
	$(GO) test -timeout 45m -v -cover
	$(BATS) ./tests
