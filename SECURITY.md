# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.2   | :white_check_mark: |
| 1.0.1   | :white_check_mark: |
| 1.0.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it by creating an issue with the "security" label. You can also contact the maintainers directly via email.

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if possible)

## Security Measures

This project takes security seriously and implements the following security measures:

1. **Regular Dependency Updates**: We use Dependabot to keep dependencies up-to-date and address security vulnerabilities.
2. **Automated Vulnerability Scanning**: The project uses OWASP Dependency-Check in CI workflows to identify vulnerable dependencies.
3. **Code Reviews**: All changes undergo code review before being merged.

## Update Policy

We aim to address critical security vulnerabilities promptly. Updates will be released as follows:

- **Critical Issues**: Within 7 days
- **High Severity Issues**: Within 14 days
- **Moderate/Low Severity Issues**: Within 30 days

## Security Best Practices for Users

When using this tool:

1. Always use the latest version
2. Be cautious when processing untrusted input files
3. Run with appropriate permissions (don't run as root/admin)