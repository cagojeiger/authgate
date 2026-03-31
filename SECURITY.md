# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting:

1. Go to **[Security Advisories](https://github.com/cagojeiger/authgate/security/advisories/new)**
2. Click **"New draft security advisory"**
3. Describe the vulnerability, reproduction steps, and impact

You will receive a response within **72 hours**.
Confirmed vulnerabilities will be patched before public disclosure, and reporters will be credited in the release notes.

## Scope

Security issues relevant to this project include:

- Authentication bypass or token forgery
- Session fixation or hijacking
- OAuth 2.0 / OIDC flow vulnerabilities
- SQL injection or data exposure
- Privilege escalation

Out of scope: vulnerabilities in upstream dependencies (report to the relevant project directly).
