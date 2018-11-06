package cmd

import (
	"testing"
)

const clientTestCert = `
-----BEGIN CERTIFICATE-----
MIIFaDCCA1ACCQCils7YtvvF0DANBgkqhkiG9w0BAQsFADB1MQswCQYDVQQGEwJG
STEQMA4GA1UECAwHVXVzaW1hYTERMA8GA1UEBwwISGVsc2lua2kxGjAYBgNVBAoM
EUhvbWUgb2YgdGhlIE1hbW1pMRIwEAYDVQQLDAlDaGFtcGlvbnMxETAPBgNVBAMM
CHJvb3QubGFuMB4XDTE4MTEwNDIxMjcwNVoXDTIwMDMzMDIxMjcwNVowdzELMAkG
A1UEBhMCRkkxEDAOBgNVBAgMB1V1c2ltYWExETAPBgNVBAcMCEhlbHNpbmtpMRow
GAYDVQQKDBFIb21lIG9mIHRoZSBNYW1taTESMBAGA1UECwwJQ2hhbXBpb25zMRMw
EQYDVQQDDApjbGllbnQubGFuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEAyKz9VqfHdUNRRD+H8m+ofqG2CoPilxAoiT7J1l3HWPjN6HtiR6jCTZAgcJUD
ROpeaJrt80BsWEHUTN/KUZl/J5Fdtg9Bfh9I5UVwELsilpgdrW8zbOmBBwo9JLuh
2ozfXjwDv9t5Z/lhO5c7DaLtk7wKMZzGI8x/Lg/EY59bGZ31/8aYn17/q3yCatbx
nEXDXzJiQBXNfOKPtbiaRplw7goQekv7soP2pvU8m+zuKSOCxxIwbv6eKJviB97f
rlObqWtpW6U5JADXun6eWW5aOqeN6rCisfRAV0l63LdYdbvruRlgpsN0DNIP9Zos
+bzYqN0gTJo5FX4qOOxyWzOqHp4aLTamwvuw5m0cd7qz32ZYemJybQb7cJoFUbh6
3hChDmsFQUYkot8jxJQfrfdvnSxUZo5SO8L0PvSpQkoJJubL5TDbUXyRXRSbXxHl
xPpW/R4v188VyeI3cj17XItqiRWZlq7nfHZwL0aR0d4SfopaI/bwZFFIhbdmjDfP
RvuRdrycn74npYOcvHh1uh3UrcvMfEl6UqjYqwETKvA6u2HDDQL1L3XY5ESa6mBW
QzRpDiWhdG2/7V4wul+wnxQOBn0GxYmWqrNxhVpzQ49f9rwfte9NxAUw6wY3EjeE
5fCXEidVezk2LXE47H+rKoM6kz28ypZNo/tpsSp8QEiBgdECAwEAATANBgkqhkiG
9w0BAQsFAAOCAgEAMm6bpMqSRZuFI69ASmHpgIKipujgj9liqIjYkAD4ZVUJEx2w
FnCmi6khpViRwJkufQZKNnjyQtBJb3vvJmtI2Je3yjuwPPsaFqMtDgfGLhMJYfDX
XyFNGXNNiV7n8LHs749wISlAM8yCrefEqcQ1VEGr3vaANDHBCWS5Pp1F9r2emxCo
bKzWKU+ZNa8UCWA/VrpY5NXUjE3kZ/tWzJZ9ZARk2lQ+2bHGCgCekhVkLn8uFKin
ojGmGnT86/zgfmAnyP75ciepZIjSNj0QyB11DBoi/5+K7/sG++tCzpaw9fkJ43eW
kTBdSreRDtrp9c6CPJ/gcL7EfkUH+qkDpWd1sju0PWkq0WHXCnz7F0XEO4dwIOG1
9L8324azB3+k4awFxzFYYIs3asTLjBYj+7ubTGl1Zs6/IvmwrOIpqv4WUEolM9mx
4cVWMXJ0l4p7kVy3BpPIc/u8kwjdt0ntYARxRsSMbxv+xli6bpupksaxmMYT8CNf
yuT3E9UmfP7+cUbhoUt45MWpJpFdhHOPx8DIZ5JCPV/zbZDzoqgk/o/xWHT/ibyb
qWKhOvgZHZFz9S1ZKA+ncQRC1lOFA/sLi1BRkqXF9YlUd/YQv95xKSpwVbQb6GqY
1JHYGmTF0U5prk3epp648T1RsU+FQZv720+bW+bSoJLRJoQMG5w0ovR3Vi0=
-----END CERTIFICATE-----
`

func TestCertFileSetFromFile(t *testing.T) {
	var cfset CertFileSet
	cfset.CertFileName = "testdata/client.crt"
	cfset.CaFileName = "testdata/root.crt"
	cfset.KeyFileName = "testdata/client.key"

	err := cfset.ReadFiles()
	if err != nil {
		t.Errorf("Could not parse certificate: %s", err)
	}
	var errs []error
	errs = cfset.CheckValidity(CheckCommonName("client.lan"))
	if len(errs) > 0 {
		for _, err = range errs {
			t.Errorf("Got some error: %s", err)
		}
	}
	cfset.CertFileName = "testdata/client-bundle.pem"
	err = cfset.ReadFiles()
	if err != nil {
		t.Errorf("Could not parse certificate: %s", err)
	}
	errs = cfset.CheckValidity(CheckCommonName("client.lan"), CheckCACommonName("root.lan"))
	if len(errs) > 0 {
		for _, err = range errs {
			t.Errorf("Got some error: %s", err)
		}
	}
}

func TestWriteFiles(t *testing.T) {
	var cfset CertFileSet
	cfset.CertFileName = "testdata/client.crt"
	cfset.CaFileName = "testdata/root.crt"
	cfset.KeyFileName = "testdata/client.key"

	cfset.ReadFiles()

	cfset.CertFileName = "testdata/client_write.crt"
	cfset.CaFileName = "testdata/root_write.crt"
	cfset.KeyFileName = "testdata/client_write.key"

	err := cfset.WriteFiles()
	if err != nil {
		t.Errorf("Could not write files: %s", err)
	}

	err = cfset.ReadFiles()
	if err != nil {
		t.Errorf("Could not read files: %s", err)
	}
	var errs []error
	errs = cfset.CheckValidity(CheckCommonName("client.lan"), CheckCACommonName("root.lan"))
	if len(errs) > 0 {
		for _, err = range errs {
			t.Errorf("Got some error: %s", err)
		}
	}
}

func TestNewCertFileSet(t *testing.T) {
	cfset := NewCertFileSet(NewBasicCert())
	if cfset.VaultRole != "" {
		t.Errorf("Expected VaultRole to be empty, got: %s", cfset.CaFileName)
	}
	cfset = NewCertFileSet(NewBasicCert(VaultRole("vault-role")))
	if cfset.VaultRole != "vault-role" {
		t.Errorf("Expected VaultRole to be 'vault-role', got: %s", cfset.CaFileName)
	}
}
