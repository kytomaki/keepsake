COUNTRY ?= FI
STATE ?= Uusimaa
LOCATION ?= Helsinki
ORGANIZATION ?= Home of the Mammi
UNIT ?= Champions
COMMON_NAME ?= internal.lan

SUBJECT = /C=$(COUNTRY)/ST=$(STATE)/L=$(LOCATION)/O=$(ORGANIZATION)/OU=$(UNIT)/CN=$(COMMON_NAME)/

.PHONY: all

all: client.crt

client.crt: COMMON_NAME = client.lan
root.crt: COMMON_NAME = root.lan

root.key:
	openssl genrsa -out $@ 4096

root.crt: root.key
	openssl req \
		-x509 \
		-new \
		-nodes \
		-key $< \
		-sha256 \
		-days 1024 \
		-subj "$(SUBJECT)" \
		-out $@

client.key:
	openssl genrsa -out $@ 4096

client.csr: client.key
	openssl req \
		-new \
		-sha256 \
		-key client.key \
		-subj "$(SUBJECT)" \
		-out client.csr

client.crt: root.crt client.csr
	openssl x509 \
		-req \
		-in client.csr \
		-CA root.crt \
		-CAkey root.key \
		-CAcreateserial \
		-days 512 \
		-sha256 \
		-out $@

client-bundle.pem: client.crt
	cat \
		root.crt \
		client.crt \
		client.key > \
		$@
		

