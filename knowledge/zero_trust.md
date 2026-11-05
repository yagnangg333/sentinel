# Zero Trust and Defence in Depth for Web Services

Zero Trust assumes no network location is trusted: every request is authenticated, authorised and encrypted, whether it comes from the internet or from inside the data centre.

## Principles applied to a web service

- Verify explicitly: authenticate every API call (tokens such as JWT or mTLS between services) and authorise per resource.
- Least privilege: run services as unprivileged users, give each service only the database permissions it needs, and segment the network so a compromised host cannot reach everything.
- Assume breach: log every request in a structured format, centralise logs, and alert on anomalies so incidents are detected quickly.

## Layered controls

A firewall restricts which ports are reachable; TLS encrypts traffic; rate limiting and request-size limits absorb abuse; input validation and parameterised queries stop injection; and log analysis with alerting catches what gets through. No single layer is assumed to be perfect.
