# Keepsake

Grab PKI keys and certificates from [HashiCorp's Vault](https://www.vaultproject.io.)

Automatically maintains keys and certificates on disk, runs command at the end of each cycle.

## Example

```
	VAULT_TOKEN=`vault token-create --policy="pki/ops/vault" --wrap-ttl 10s --format=json --ttl=60m | jq -r ".wrap_info.token"`
	keepsake update --config keepsake.yaml
```

This will update the certificates as specified by `keepsake.yaml` if needed.

## Configuration

keepsake uses https://github.com/spf13/viper to manage configuration. Basic configuration examples can be found in [test-data](testdata/keepsake-example-config.yaml) and [docker](docker/keepsake.yaml) directories.

```yaml
---
vault_address: http://vault:8200              # vault server's address
vault_token: keepsake-vault-client            # vault-token, can also be set using environment variable VAULT_TOKEN
vault_pki-path: pki                           # vault's pki endpoint's path
renewal_coefficient: 0.9                      # Renewal coefficient sets the multiplier for durations on update, should be set under 1
certificates:                                 # List of certificates we wan't to monitor
  - cname: certset.keepsake.com               # CNAME for the certificate
    altnames:                                 # Alternative names
      - foo.keepsake.com
    vaultrole: keepsake                       # Role in vault
    ttl: 10m                                  # Time to live for the certificate
    cert: docker/keepsake_client.crt          # Path to certificate file
    key: docker/keepsake_client.key           # Path to certificate key
    root: docker/root1.crt                    # Path to CA certificate file
    cmd: 'echo updated certset'               # Command to run in case certificate is updated
    ipaddresses:                              # Ip-addresses of the certificate
      - "127.0.0.1"
      - "10.10.10.10"
    tests:                                    # Validity tests of the certificate
      cname: ""                               # Tests for certificate file's CNAME matches the CNAME specified
      cacname: keepsake                       # Tests that the root certificates CNAME matches the value given ("keepsake" in this case)
      ttl: ""                                 # Runs the ttl test
  - cname: certset2.keepsake.com              # These are a same kind of a certificate definition
    vaultrole: keepsake
    ttl: 10s
    cert: docker/keepsake_client2.crt
    key: docker/keepsake_client2.key
    root: docker/root2.crt
    cmd: 'echo updated certset2'
    ipaddresses:
      - "127.0.0.1"
    tests:
      cname: ""
      cacname: keepsake
      ttl: ""
  - cname: certset-bundle.keepsake.com        # This is an example on how to add a certificate bundle definition
    vaultrole: keepsake
    ttl: 15s
    bundle: docker/keepsake_client_bundle.pem # Certificate bundle file containing the root, intermediate and client certificates
    key: docker/keepsake_client.key
    cmd: 'echo updated bundle'
    ipaddresses:
      - "127.0.0.1"
    tests:
      cname: ""
      cacname: keepsake
      ttl: ""
```

## Further development and testing

Simple dockerized integration test can be run by `make docker-integration-test`.
This will start a dockerized vault. Initializes the `pki` backend to handle
certificates in the vault. Then runs a build within a amazonlinux container and
executes the `keepsake` with the [docker/keepsake.yaml](docker/keepsake.yaml)
as the configuration file.

To clean up after testing one can use `make docker-clean` to stop the
containers and remove the build time images.

Once the vault container is running. `docker-compose run amzn bash` Enables
one to inspect the keepsake in it's native environment. And helps the
development since the working directory is mounted in the container as
`/root/go/src/github.com/hmhco/keepsake`

E.g.
```sh
	docker-compose run amzn bash
	cd /root/go/src/github.com/hmhco/keepsake
	go run main.go update daemon --config docker/keepsake.yaml
```
