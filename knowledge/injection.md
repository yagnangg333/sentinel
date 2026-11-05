# Injection Attacks: SQL Injection, XSS and Command Injection

Injection attacks place attacker-controlled code into a query, page or shell command. MITRE ATT&CK: T1190 Exploit Public-Facing Application.

## SQL injection indicators

Request parameters containing `' OR '1'='1`, `OR 1=1`, `UNION SELECT`, `information_schema`, `SLEEP(` (time-based blind injection), `; DROP TABLE` or a trailing `--` comment. Automated tools such as sqlmap send hundreds of variations and often identify themselves in the User-Agent.

## Cross-site scripting (XSS) indicators

Parameters containing `<script>`, `javascript:`, `onerror=`, `onload=` or SVG elements with event handlers. Reflected XSS steals sessions from users who click a crafted link.

## Command injection indicators

Shell metacharacters followed by commands: `;cat /etc/passwd`, `| id`, `&& whoami`, `$(curl ...)` or backticks. This is the most severe class because it can lead to full remote code execution.

## Response

1. Identify the endpoint and parameter that was targeted and whether any attempt returned 2xx with an unusual response size.
2. Review application and database logs for the same time window.
3. Block the source and add a WAF rule for the payload pattern as a temporary mitigation.

## Prevention

Use parameterised queries or an ORM for every database call; never concatenate input into SQL. Encode output for its context (HTML, attribute, JavaScript) and set a Content-Security-Policy. Avoid invoking a shell; pass arguments as an array to process APIs. Validate input against an allow-list.
