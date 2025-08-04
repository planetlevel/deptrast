# Security Setup Guide

This document outlines the security setup required for this project, particularly for running security scans and dependency checks properly.

## NVD API Key Setup

The OWASP Dependency Check tool uses the National Vulnerability Database (NVD) to scan for vulnerabilities. Without an API key, the updates can be extremely slow.

### Step 1: Request an NVD API Key

1. Visit the [NVD API Key Request Page](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill out the form with your information
3. You will receive an API key via email

### Step 2: Set Up the API Key in GitHub

1. Navigate to your GitHub repository
2. Go to Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Create a new secret with:
   - Name: `NVD_API_KEY`
   - Value: The API key you received from NVD
5. Click "Add secret" to save it

### Step 3: Verify Configuration

The GitHub Actions workflows are already configured to use the API key. They include this parameter:

```
-DnvdApiKey=${{ secrets.NVD_API_KEY }}
```

## Local Development Security Configuration

For running dependency checks locally, create a Maven settings.xml file that includes your NVD API key:

```xml
<settings>
  <profiles>
    <profile>
      <id>security</id>
      <properties>
        <nvdApiKey>your-nvd-api-key-here</nvdApiKey>
      </properties>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>security</activeProfile>
  </activeProfiles>
</settings>
```

Then run dependency checks with:

```bash
mvn org.owasp:dependency-check-maven:check
```

## Security Policies

See [SECURITY.md](../SECURITY.md) for information about the project's security policy, vulnerability reporting procedures, and best practices.