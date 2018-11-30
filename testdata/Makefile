COUNTRY ?= FI
STATE ?= Uusimaa
LOCATION ?= Helsinki
ORGANIZATION ?= Home of the Mammi
UNIT ?= Champions
COMMON_NAME ?= internal.lan
CERTIFICATE_BITS ?= 512
CERTS ?= \
	keepsake_client \
	keepsake_client2 

SUBJECT = /C=$(COUNTRY)/ST=$(STATE)/L=$(LOCATION)/O=$(ORGANIZATION)/OU=$(UNIT)/CN=$(COMMON_NAME)/
GENERATED_CERTS := \
	$(addsuffix .csr, $(CERTS)) \
	$(addsuffix .key, $(CERTS)) \
	$(addsuffix .crt, $(CERTS))

.PHONY: all
all: $(GENERATED_CERTS) root.key root.crt keepsake_client_bundle.pem

.PHONY: clean
clean:
	-rm *.crt *.key *.csr *.pem

root.crt: COMMON_NAME = keepsake
keepsake_client.csr: COMMON_NAME = certset.keepsake.com
keepsake_client2.csr: COMMON_NAME = certset2.keepsake.com

root.key:
	openssl genrsa -out $@ $(CERTIFICATE_BITS)

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

%.key:
	openssl genrsa -out $@ $(CERTIFICATE_BITS)

%.csr: %.key
	openssl req \
		-new \
		-sha256 \
		-key $*.key \
		-subj "$(SUBJECT)" \
		-out $@

%.crt: root.crt %.csr
	openssl x509 \
		-req \
		-in $*.csr \
		-CA root.crt \
		-CAkey root.key \
		-CAcreateserial \
		-days 512 \
		-sha256 \
		-out $@

%_bundle.pem: %.crt
	cat \
		root.crt \
		$*.crt \
		> $@ 

