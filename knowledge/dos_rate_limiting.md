# Denial of Service and Rate Limiting

Application-layer (Layer 7) denial of service floods a server with valid-looking HTTP requests to exhaust threads, memory or CPU. MITRE ATT&CK: T1499 Endpoint Denial of Service.

## Indicators

Hundreds of requests per minute from a single IP, many HTTP 429 Too Many Requests responses that the client ignores, rising 503 Service Unavailable responses when the server's worker queue is full, and growing latency. A distributed attack spreads the same pattern across many IPs.

## Token-bucket rate limiting

Each client gets a bucket holding up to B tokens (the burst size) that refills at R tokens per second. Each request consumes one token; with an empty bucket the server answers 429 with a Retry-After header. This allows short bursts while capping the sustained rate.

## Response

1. Confirm the source (single IP, subnet, or distributed) from the access log.
2. Block abusive IPs at the firewall or load balancer, which is cheaper than rejecting them in the application.
3. Lower per-IP limits temporarily and enable upstream DDoS protection or a CDN for large attacks.

## Prevention

Use bounded queues so overload produces fast 503s instead of unbounded memory growth, set timeouts on idle and slow connections (protects against Slowloris), cap header and body sizes, and put rate limits in front of expensive endpoints.
