# Publishing Deptrast to Maven Central

## Overview
This guide walks through publishing deptrast to Maven Central using the Sonatype Central Portal.

## Prerequisites

### 1. Maven Central Account
1. Go to https://central.sonatype.com
2. Sign in with GitHub (planetlevel account)
3. Register the namespace `com.contrastsecurity`
4. Verify namespace ownership:
   - GitHub verification: Add the provided verification key to the deptrast repo description temporarily
   - Or DNS verification: Add TXT record to contrastsecurity.com domain

### 2. GPG Key Setup

You need a GPG key to sign your artifacts.

**Check if you have a key:**
```bash
gpg --list-secret-keys --keyid-format=long
```

**If you don't have a key, create one:**
```bash
gpg --gen-key
```
- Use your name: Jeff Williams
- Use your email: jeff.williams@contrastsecurity.com
- Choose a strong passphrase (save it securely!)

**Publish your public key:**
```bash
# Get your key ID (the 8-character hex after 'rsa4096/')
gpg --list-secret-keys --keyid-format=short

# Publish to key servers
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
gpg --keyserver keys.openpgp.org --send-keys YOUR_KEY_ID
```

**Export for backup:**
```bash
# Backup your keys (store securely!)
gpg --export-secret-keys YOUR_KEY_ID > ~/deptrast-gpg-secret.key
gpg --export YOUR_KEY_ID > ~/deptrast-gpg-public.key
```

### 3. Maven Settings

Create or update `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>YOUR_SONATYPE_USERNAME</username>
      <password>YOUR_SONATYPE_TOKEN</password>
    </server>
  </servers>

  <profiles>
    <profile>
      <id>ossrh</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <gpg.executable>gpg</gpg.executable>
        <gpg.passphrase>YOUR_GPG_PASSPHRASE</gpg.passphrase>
      </properties>
    </profile>
  </profiles>
</settings>
```

**Get your Sonatype token:**
1. Go to https://central.sonatype.com
2. Click your username → View Account
3. Generate a User Token
4. Use the token as username/password in settings.xml

## Building and Publishing

### 1. Verify Everything Builds

```bash
# Clean build with all artifacts
mvn clean verify

# This should create:
# - target/deptrast-3.0.0.jar (shaded jar)
# - target/deptrast-3.0.0-sources.jar
# - target/deptrast-3.0.0-javadoc.jar
# - All .asc signature files
```

### 2. Deploy to Central

```bash
# Deploy and publish to Maven Central
mvn clean deploy

# This will:
# 1. Build all artifacts
# 2. Sign them with GPG
# 3. Upload to Central Portal
# 4. Automatically publish (if configured)
```

### 3. Manual Publishing (if auto-publish disabled)

If automatic publishing is disabled:
1. Go to https://central.sonatype.com
2. Navigate to "Deployments"
3. Find your deployment
4. Review artifacts
5. Click "Publish"

## Version Management

### Before Each Release

1. **Update version in pom.xml:**
   ```xml
   <version>3.0.0</version>  <!-- No -SNAPSHOT for releases -->
   ```

2. **Commit and tag:**
   ```bash
   git add pom.xml
   git commit -m "Release version 3.0.0"
   git tag -a v3.0.0 -m "Version 3.0.0"
   git push origin main --tags
   ```

3. **Deploy to Central** (as shown above)

4. **Bump to next development version:**
   ```xml
   <version>3.0.1-SNAPSHOT</version>
   ```
   ```bash
   git add pom.xml
   git commit -m "Bump to 3.0.1-SNAPSHOT"
   git push origin main
   ```

## Troubleshooting

### GPG Issues

**"gpg: signing failed: No secret key"**
- Check: `gpg --list-secret-keys`
- Make sure the key hasn't expired
- Verify gpg.passphrase in settings.xml

**"gpg: signing failed: Inappropriate ioctl for device"**
```bash
export GPG_TTY=$(tty)
```
Add this to your `~/.bashrc` or `~/.zshrc`

### Maven Central Issues

**"401 Unauthorized"**
- Verify your token in `~/.m2/settings.xml`
- Token may have expired - generate new one
- Server ID must match: `<id>central</id>`

**"Namespace not verified"**
- Complete namespace verification in Central Portal
- May take a few minutes to propagate

**"Missing required metadata"**
- Verify POM has: name, description, url, license, developers, scm
- Check with: `mvn help:effective-pom`

### Validation

**Test the published artifact:**
```bash
# Wait ~10 minutes for sync to Maven Central
# Search: https://search.maven.org

# Test in a new project:
<dependency>
    <groupId>com.contrastsecurity</groupId>
    <artifactId>deptrast</artifactId>
    <version>3.0.0</version>
</dependency>
```

## Resources

- Maven Central Portal: https://central.sonatype.com
- Publishing Guide: https://central.sonatype.org/publish/publish-portal-maven/
- Requirements: https://central.sonatype.org/publish/requirements/
- GPG Guide: https://central.sonatype.org/publish/requirements/gpg/

## Security Notes

- **NEVER commit** `~/.m2/settings.xml` to version control
- **NEVER commit** GPG private keys
- Store GPG passphrase securely (password manager)
- Backup your GPG keys in a secure location
- Once published to Central, artifacts **CANNOT be deleted** (only marked as deprecated)
