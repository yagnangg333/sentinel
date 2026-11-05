# Brute Force and Credential Stuffing

Attackers try many passwords for one account (brute force), one password across many accounts (password spraying), or leaked username and password pairs (credential stuffing). MITRE ATT&CK: T1110 Brute Force.

## Indicators

A burst of 401 or 403 responses from one IP against a login or authentication endpoint, many different usernames from the same source, or the same username from many IPs (distributed attack). A sudden 200 after many failures may mean a successful guess.

## Response

1. Check whether any account received a successful login after a run of failures; if so, force a password reset and revoke its sessions.
2. Temporarily block the source IPs and enable stricter rate limits on the authentication endpoint.

## Prevention

Enforce multi-factor authentication, rate-limit and progressively delay failed logins per account and per IP, and check new passwords against breached-password lists. Return the same error message for unknown user and wrong password.
