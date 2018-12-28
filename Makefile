PACKAGE  = keepsake
DATE    ?= $(shell date +%FT%T%z)
VERSION ?= $(shell git describe --tags)
COMMIT  := $(shell git log --pretty=format:'%h' -n 1)

DESTDIR ?= build
prefix ?= /usr
bindir := $(DESTDIR)$(prefix)/bin

CONFIG_FILES := \
	$(DESTDIR)/etc/$(PACKAGE).yaml \
	$(DESTDIR)/etc/init/$(PACKAGE).conf \
	$(DESTDIR)/etc/sysconfig/$(PACKAGE)

PACKAGE_FILES := \
	$(CONFIG_FILES) \
	$(bindir)/$(PACKAGE) \
	$(DESTDIR)/var/log/$(PACKAGE)

AMAZONLINUX_VERSION := 2017.09

.PHONY: all
all: bin/$(PACKAGE)

bin/$(PACKAGE): vendor
	go build \
		-tags release \
		-ldflags '-X github.com/hmhco/keepsake/cmd.Version=$(VERSION) -X github.com/hmhco/keepsake/cmd.BuildDate=$(DATE) -X github.com/hmhco/keepsake/cmd.Commit=$(COMMIT)' \
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
package: $(PACKAGE_FILES)
	cd /root/go/src/github.com/hmhco/keepsake
	fpm \
		-s dir \
		-t rpm \
		-n $(PACKAGE) \
		-v $(VERSION) \
		-C $(DESTDIR) \
		$(addprefix --config-files , $(patsubst $(DESTDIR)/%,%,$(CONFIG_FILES))) \
		$(patsubst $(DESTDIR)/%,%,$(PACKAGE_FILES))

.PHONY: amzn
amzn: docker/Dockerfile_amzn
	docker-compose run amzn bash -c 'make -C /root/go/src/github.com/hmhco/keepsake clean package'

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
	@echo Running docker integration test against dockerized vault
	@echo The log lines should not report any errors
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

# Packaging related

$(bindir)/$(PACKAGE): bin/$(PACKAGE) $(bindir)
	install \
		-m 0555 \
		$< \
		$@

$(DESTDIR)/etc/init/$(PACKAGE).conf: packaging/upstart.conf $(DESTDIR)/etc/init $(DESTDIR)/etc
	install \
		-m 0444 \
		$< \
		$@

$(DESTDIR)/etc/$(PACKAGE).yaml: packaging/keepsake.yaml $(DESTDIR)/etc
	install \
		$< \
		$@

$(DESTDIR)/etc/sysconfig/$(PACKAGE): packaging/sysconfig $(DESTDIR)/etc/sysconfig $(DESTDIR)/etc
	install \
		$< \
		$@

$(DESTDIR)/%:
	install \
		-d \
		$@
