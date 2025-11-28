# Publishing to Maven Central - Quick Start

## TL;DR - Steps to Publish

### One-Time Setup (Do Once)

1. **Register at Maven Central**
   - https://central.sonatype.com → Sign in with GitHub
   - Register namespace: `com.contrastsecurity`
   - Verify via GitHub repo description or DNS

2. **Create/Get GPG Key**
   ```bash
   # Check if you have one
   gpg --list-secret-keys --keyid-format=short

   # If not, create one
   gpg --gen-key

   # Publish it
   gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID
   ```

3. **Configure Maven Settings** (`~/.m2/settings.xml`)
   ```xml
   <settings>
     <servers>
       <server>
         <id>central</id>
         <username>YOUR_SONATYPE_TOKEN_USERNAME</username>
         <password>YOUR_SONATYPE_TOKEN_PASSWORD</password>
       </server>
     </servers>
     <profiles>
       <profile>
         <id>ossrh</id>
         <activation><activeByDefault>true</activeByDefault></activation>
         <properties>
           <gpg.executable>gpg</gpg.executable>
           <gpg.passphrase>YOUR_GPG_PASSPHRASE</gpg.passphrase>
         </properties>
       </profile>
     </profiles>
   </settings>
   ```

### Every Release

1. **Update version** (remove -SNAPSHOT)
   ```bash
   # Edit pom.xml: <version>3.0.0</version>
   ```

2. **Commit and tag**
   ```bash
   git add pom.xml
   git commit -m "Release version 3.0.0"
   git tag -a v3.0.0 -m "Version 3.0.0"
   git push origin main --tags
   ```

3. **Deploy to Maven Central**
   ```bash
   mvn clean deploy
   ```

4. **Bump to next dev version**
   ```bash
   # Edit pom.xml: <version>3.0.1-SNAPSHOT</version>
   git add pom.xml
   git commit -m "Bump to 3.0.1-SNAPSHOT"
   git push origin main
   ```

5. **Wait ~10 min**, then verify at https://search.maven.org

## What's Been Done

✅ POM updated with all Maven Central requirements:
- Description, URL, license (MIT)
- Developer info (Jeff Williams)
- SCM details (GitHub repo)
- Plugins for sources JAR
- Plugins for javadoc JAR (version 3.6.3 for Java 11 compatibility)
- GPG signing plugin
- Central publishing plugin

✅ Build verified - creates all required artifacts:
- `deptrast-3.0.1.jar` (main artifact, 14 MB shaded)
- `deptrast-3.0.1-sources.jar` (35 KB)
- `deptrast-3.0.1-javadoc.jar` (399 KB)

**Note:** Using maven-javadoc-plugin 3.6.3 (not 3.11.2) to maintain Java 11 compatibility.

## Need Help?

See [PUBLISHING.md](PUBLISHING.md) for:
- Detailed setup instructions
- Troubleshooting common issues
- Security best practices
- GPG key management

## Quick Test

```bash
# Verify build works
mvn clean package -Dmaven.test.skip=true

# Check artifacts
ls -lh target/deptrast-3.0.0*.jar
```
