PACKAGE  = keepsake
DATE    ?= $(shell date +%FT%T%z)
VERSION ?= $(shell git describe --tags --always --dirty 2> /dev/null || \
			cat $(CURDIR)/.version 2> /dev/null || echo v0)
COMMIT  := $(shell git log --pretty=format:'%h' -n 1)
GOPATH   = $(CURDIR)/.gopath~
BIN      = $(GOPATH)/bin
BASE     = $(GOPATH)/src/$(PACKAGE)
PKGS     = $(or $(PKG),$(shell cd $(BASE) && env GOPATH=$(GOPATH) $(GO) list ./... | grep -v "github"| grep -v "golang.org"))
TESTPKGS = $(shell env GOPATH=$(GOPATH) $(GO) list -f '{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' $(PKGS))

AMAZONLINUX_VERSION := 2017.09

GO      = go
GODOC   = godoc
GOFMT   = gofmt
TIMEOUT = 15
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.PHONY: all
all: fmt lint vendor | $(BASE) ; $(info $(M) building executable…) @ ## Build program binary
	$Q cd $(BASE) && $(GO) build \
		-tags release \
		-ldflags '-X main.version=$(VERSION) -X main.buildDate=$(DATE) -X main.commit=$(COMMIT)' \
		-o bin/$(PACKAGE) main.go

$(BASE): ; $(info $(M) setting GOPATH…)
	@mkdir -p $(dir $@)
	@ln -sf $(CURDIR) $@

# Tools

GOLINT = $(BIN)/golint
$(BIN)/golint: | $(BASE) ; $(info $(M) building golint…)
	$Q go get github.com/golang/lint/golint

GOCOVMERGE = $(BIN)/gocovmerge
$(BIN)/gocovmerge: | $(BASE) ; $(info $(M) building gocovmerge…)
	$Q go get github.com/wadey/gocovmerge

GOCOV = $(BIN)/gocov
$(BIN)/gocov: | $(BASE) ; $(info $(M) building gocov…)
	$Q go get github.com/axw/gocov/...

GOCOVXML = $(BIN)/gocov-xml
$(BIN)/gocov-xml: | $(BASE) ; $(info $(M) building gocov-xml…)
	$Q go get github.com/AlekSi/gocov-xml

GO2XUNIT = $(BIN)/go2xunit
$(BIN)/go2xunit: | $(BASE) ; $(info $(M) building go2xunit…)
	$Q go get github.com/tebeka/go2xunit

# Tests

TEST_TARGETS := test-default test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) test-xml check test tests
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode with coverage reporting
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
check test tests: fmt lint vendor | $(BASE) ; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests
	$Q cd $(BASE) && $(GO) test -timeout $(TIMEOUT)s $(ARGS) $(TESTPKGS)

test-xml: fmt lint vendor | $(BASE) $(GO2XUNIT) ; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests with xUnit output
	$Q cd $(BASE) && 2>&1 $(GO) test -timeout 20s -v $(TESTPKGS) | tee test/tests.output
	$(GO2XUNIT) -fail -input test/tests.output -output test/tests.xml

COVERAGE_MODE = atomic
COVERAGE_PROFILE = $(COVERAGE_DIR)/profile.out
COVERAGE_XML = $(COVERAGE_DIR)/coverage.xml
COVERAGE_HTML = $(COVERAGE_DIR)/index.html
.PHONY: test-coverage test-coverage-tools
test-coverage-tools: | $(GOCOVMERGE) $(GOCOV) $(GOCOVXML)
test-coverage: COVERAGE_DIR := $(CURDIR)/test/coverage.$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
test-coverage: fmt lint vendor test-coverage-tools | $(BASE) ; $(info $(M) running coverage tests…) @ ## Run coverage tests
	$Q mkdir -p $(COVERAGE_DIR)/coverage
	$Q cd $(BASE) && for pkg in $(TESTPKGS); do \
		$(GO) test \
			-coverpkg=$$($(GO) list -f '{{ join .Deps "\n" }}' $$pkg | \
					grep '^$(PACKAGE)/' | grep -v '^$(PACKAGE)/vendor/' | \
					tr '\n' ',')$$pkg \
			-covermode=$(COVERAGE_MODE) \
			-coverprofile="$(COVERAGE_DIR)/coverage/`echo $$pkg | tr "/" "-"`.cover" $$pkg ;\
	 done
	$Q $(GOCOVMERGE) $(COVERAGE_DIR)/coverage/*.cover > $(COVERAGE_PROFILE)
	$Q $(GO) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	$Q $(GOCOV) convert $(COVERAGE_PROFILE) | $(GOCOVXML) > $(COVERAGE_XML)

.PHONY: lint
lint: vendor | $(BASE) $(GOLINT) ; $(info $(M) running golint…) @ ## Run golint
	$Q cd $(BASE) && ret=0 && for pkg in $(PKGS); do \
		test -z "$$($(GOLINT) $$pkg | tee /dev/stderr)" || ret=1 ; \
	 done ; exit $$ret

.PHONY: fmt
fmt: ; $(info $(M) running gofmt…) @ ## Run gofmt on all source files
	@ret=0 && for d in $$($(GO) list -f '{{.Dir}}' ./... | grep -v /vendor/); do \
		$(GOFMT) -l -w $$d/*.go || ret=$$? ; \
	 done ; exit $$ret

# Dependency management

Gopkg.lock: Gopkg.toml | $(BASE) ; $(info $(M) updating dependencies…)
	$Q cd $(BASE) && dep ensure -update
	@touch $@
vendor: Gopkg.lock | $(BASE) ; $(info $(M) retrieving dependencies…)
	$Q cd $(BASE) && dep ensure
	@ln -sf . vendor/src
	@touch $@

# Packaging
.PHONY: package
package: clean fmt lint vendor all
	cd /rpmbuild
	fpm -s dir -t rpm -n $(PACKAGE) -v $(VERSION) --prefix /usr/local bin/keepsake

.PHONY: amzn
amzn: docker/Dockerfile_amzn
	docker-compose run amzn bash -c 'make -C /rpmbuild package'

# Addtional dependencies needed for building docker image
docker/Dockerfile_amzn:

docker/Dockerfile_vault: docker/generate-vault-ca.sh

docker/Dockerfile_%: Dockerfile_%.template docker-compose.yml
	sed \
		-e 's|@AMAZONLINUX_VERSION@|$(AMAZONLINUX_VERSION)|g' \
		$< > $@
	docker-compose build $*|| \
		(rm -f $@ && exit 1)

# Clean up docker-compose related clutter
.PHONY: docker-clean
docker-clean:
	-docker-compose down \
		--rmi all \
		--volumes \
		--remove-orphans
	-rm -f docker/Dockerfile_*

.PHONY: integration-test
integration-test: all
	bin/keepsake \
		-cn keepsake.com \
		-certFile keepsake.crt \
		-keyFile keepsake.key \
		-caFile keepsake.ca \
		-vault-role keepsake \
		-cmd 'echo updated' \
		-certTTL=1m \
		-json \
		-once

.PHONY: docker-integration-test
docker-integration-test: docker/Dockerfile_amzn docker/Dockerfile_vault
	docker-compose up -d vault
	docker-compose exec -T vault sh /generate-vault-ca.sh
	docker-compose run amzn bash -c 'make -C /rpmbuild integration-test'

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	@rm -rf $(GOPATH)
	@rm -rf bin
	@rm -rf vendor
	@rm -rf test/tests.* test/coverage.*
	@rm -rf keepsake-*.rpm

.PHONY: help
help:
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: version
version:
	@echo $(VERSION)
