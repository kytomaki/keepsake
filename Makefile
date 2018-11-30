PACKAGE  = keepsake
DATE    ?= $(shell date +%FT%T%z)
VERSION ?= $(shell git describe --tags)
COMMIT  := $(shell git log --pretty=format:'%h' -n 1)

AMAZONLINUX_VERSION := 2017.09

.PHONY: all
all: bin/$(PACKAGE)

bin/$(PACKAGE): vendor
	go build \
		-tags release \
		-ldflags '-X main.version=$(VERSION) -X main.buildDate=$(DATE) -X main.commit=$(COMMIT)' \
		-o bin/$(PACKAGE) main.go

# Dependency management

Gopkg.lock: Gopkg.toml
	dep ensure -update
	@touch $@
vendor: Gopkg.lock
	dep ensure
	@touch $@

# Packaging
.PHONY: package
package: bin/$(PACKAGE)
	cd /root/go/src/keepsake
	fpm -s dir -t rpm -n $(PACKAGE) -v $(VERSION) --prefix /usr/local bin/keepsake

.PHONY: amzn
amzn: docker/Dockerfile_amzn
	docker-compose run amzn bash -c 'make -C /root/go/src/keepsake clean package'

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
	bin/keepsake update 

.PHONY: docker-integration-test
docker-integration-test: docker/Dockerfile_amzn docker/Dockerfile_vault
	docker-compose up -d vault
	docker-compose exec -T vault sh /generate-vault-ca.sh
	docker-compose run amzn bash -c 'make -C /root/go/src/github.com/hmhco/keepsake integration-test'

# Misc

.PHONY: clean
clean:
	@rm -rf bin
	@rm -rf vendor
	@rm -rf test/tests.* test/coverage.*
	@rm -rf keepsake-*.rpm

.PHONY: version
version:
	@echo $(VERSION)
