# DANE certificate fixtures

These fixtures contain a self-signed RSA certificate and its exact DER
`SubjectPublicKeyInfo`. The certificate is test data only. Its private key is
not tracked and the engine never needs a private key.

They were generated with OpenSSL 3.5.6:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=dane.fixture -days 3650 \
  -keyout fixture-key.pem -out fixture-cert.pem
openssl x509 -in fixture-cert.pem -outform DER -out fixture-cert.der
openssl x509 -in fixture-cert.pem -pubkey -noout |
  openssl pkey -pubin -outform DER -out fixture-spki.der
```

The tracked hexadecimal encoding is whitespace-insensitive. Sizes and
SHA-256 digests of the decoded DER are pinned in `manifest.toml`.
