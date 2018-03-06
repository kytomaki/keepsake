#!/bin/sh
set eou
set +x
# login to vault with a root token
vault login keepsake-test
# enable ca functionality
vault secrets enable pki
# Generate root certificate
vault write pki/root/generate/internal \
	common_name=keepsake \
	ttl=60m
# Update CRL
vault write pki/config/urls \
	issuing_certificates="http://vault:8200/v1/pki/ca" \
	crl_distribution_points="http://vault:8200/v1/pki/crl"
# Configure test role
vault write pki/roles/keepsake \
    allowed_domains=keepsake_default \
    allow_subdomains=true \
    allow_any_name=true \
    max_ttl=30s
# issue client token
vault token create \
	-id=keepsake-vault-client \
	-ttl=6m
