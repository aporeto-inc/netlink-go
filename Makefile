ci: init lint test

init:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure
	dep status

lint:
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	@ golangci-lint run \
		--deadline=5m \
		--disable-all \
		--exclude-use-default=false \
		--enable=errcheck \
		--enable=goimports \
		--enable=ineffassign \
		--enable=govet \
		--enable=golint \
		--enable=unused \
		--enable=structcheck \
		--enable=varcheck \
		--enable=deadcode \
		--enable=unconvert \
		--enable=goconst \
		--enable=gosimple \
		--enable=misspell \
		--enable=staticcheck \
		--enable=unparam \
		--enable=prealloc \
		--enable=nakedret \
		--enable=typecheck \
		./...

test:
	@ for d in `go list ./... | grep -v vendor`; do \
		go test -race -coverprofile=profile.out -covermode=atomic "$${d}"; \
		if [ -f profile.out ]; then cat profile.out >> coverage.txt; rm -f profile.out; fi \
	done
