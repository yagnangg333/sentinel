# TLS Hardening

TLS protects data in transit with encryption, integrity and server authentication.

## Recommended configuration

Allow only TLS 1.2 and TLS 1.3; disable SSLv3, TLS 1.0 and TLS 1.1, which are vulnerable to attacks such as POODLE and BEAST. Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) with forward secrecy (ECDHE key exchange). Disable TLS compression (CRIME). Send `Strict-Transport-Security` (HSTS) so browsers refuse plain HTTP afterwards.

## Certificates

Use certificates from a trusted CA in production (for example Let's Encrypt), automate renewal, and include the correct Subject Alternative Names. Self-signed certificates are fine for local testing only. Protect the private key with file permissions readable only by the server user.

## Monitoring

Watch for spikes in TLS handshake failures, which can indicate scanners probing for old protocol versions or misconfigured clients, and for expiring certificates.
