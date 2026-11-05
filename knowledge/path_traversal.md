# Path Traversal (Directory Traversal)

Path traversal lets an attacker read files outside the web root by putting `../` sequences, or encoded forms such as `%2e%2e%2f`, `..%2f` and double-encoded `%252e%252e`, into a URL. Typical targets are `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, application config files and, on Windows, `win.ini`. MITRE ATT&CK: T1190 Exploit Public-Facing Application.

## How to recognise it in access logs

Look for `..` segments after URL decoding, absolute system paths such as `/etc/passwd` in the request target, and many variations of the same request from one IP. A response of 403 or 404 means the server refused; a 200 response to a traversal attempt is a possible compromise and must be investigated immediately.

## Immediate response

1. Check whether any traversal request returned 200. If so, treat the requested file as disclosed: rotate any secrets it contained.
2. Block the source IP at the firewall or WAF for the duration of the investigation.
3. Search the logs for other activity from the same IP (scanning, injection attempts) to scope the incident.

## Prevention

Canonicalise the path (decode, then resolve with `realpath`) and verify that the result is still inside the document root. Reject any `..` segment outright. Never build file paths directly from user input. Run the server as an unprivileged user so even a successful traversal reads as little as possible.
