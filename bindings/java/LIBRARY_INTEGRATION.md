# QUAC 100 Java SDK - Library Integration Guide

This guide explains how to add the QUAC 100 Java SDK as a library dependency in your Java projects.

## Table of Contents

1. [Maven Integration](#maven-integration)
2. [Gradle Integration](#gradle-integration)
3. [Manual JAR Integration](#manual-jar-integration)
4. [Native Library Setup](#native-library-setup)
5. [IDE Configuration](#ide-configuration)
6. [Troubleshooting](#troubleshooting)

---

## Maven Integration

### From Maven Central (Recommended)

Add the following dependency to your `pom.xml`:

```xml
<dependencies>
    <dependency>
        <groupId>com.dyber</groupId>
        <artifactId>quac100</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>
```

### From Local Repository

If the SDK is not published to Maven Central, install it locally first:

```bash
# Navigate to the Java SDK directory
cd quantacore-sdk/bindings/java

# Install to local Maven repository
mvn clean install -DskipTests
```

Then add the dependency as shown above.

### From GitHub Packages

If using GitHub Packages, add the repository:

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/dyber-pqc/quantacore-sdk</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.dyber</groupId>
        <artifactId>quac100</artifactId>
        <version>1.0.0</version>
    </dependency>
</dependencies>
```

Configure authentication in `~/.m2/settings.xml`:

```xml
<servers>
    <server>
        <id>github</id>
        <username>YOUR_GITHUB_USERNAME</username>
        <password>YOUR_GITHUB_TOKEN</password>
    </server>
</servers>
```

---

## Gradle Integration

### Kotlin DSL (build.gradle.kts)

```kotlin
repositories {
    mavenCentral()
    // For local builds:
    mavenLocal()
}

dependencies {
    implementation("com.dyber:quac100:1.0.0")
}
```

### Groovy DSL (build.gradle)

```groovy
repositories {
    mavenCentral()
    // For local builds:
    mavenLocal()
}

dependencies {
    implementation 'com.dyber:quac100:1.0.0'
}
```

### From Local JAR File

```kotlin
dependencies {
    implementation(files("libs/quac100-1.0.0.jar"))
}
```

---

## Manual JAR Integration

### Step 1: Build the JAR

```bash
cd quantacore-sdk/bindings/java
mvn clean package -DskipTests
```

This creates:
- `target/quac100-1.0.0.jar` - Main JAR
- `target/quac100-1.0.0-sources.jar` - Sources
- `target/quac100-1.0.0-javadoc.jar` - Documentation

### Step 2: Copy JAR to Your Project

```bash
mkdir -p your-project/libs
cp target/quac100-1.0.0.jar your-project/libs/
```

### Step 3: Add to Classpath

**Command Line:**
```bash
javac -cp "libs/quac100-1.0.0.jar:." YourApp.java
java -cp "libs/quac100-1.0.0.jar:." YourApp
```

**IDE Project Settings:**
Add the JAR to your project's build path/libraries.

---

## Native Library Setup

The Java SDK requires native libraries to function. There are several ways to provide them:

### Option 1: System Library Path (Recommended for Production)

Copy native libraries to system paths:

**Windows:**
```batch
copy quac100_jni.dll C:\Windows\System32\
copy quac100.dll C:\Windows\System32\
```

Or add to PATH:
```batch
set PATH=%PATH%;C:\path\to\native\libs
```

**Linux:**
```bash
sudo cp libquac100_jni.so /usr/local/lib/
sudo cp libquac100.so /usr/local/lib/
sudo ldconfig
```

Or set LD_LIBRARY_PATH:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/native/libs
```

**macOS:**
```bash
sudo cp libquac100_jni.dylib /usr/local/lib/
sudo cp libquac100.dylib /usr/local/lib/
```

Or set DYLD_LIBRARY_PATH:
```bash
export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/path/to/native/libs
```

### Option 2: java.library.path (Recommended for Development)

Specify at runtime:

```bash
java -Djava.library.path=/path/to/native/libs -jar your-app.jar
```

**Maven Surefire Plugin:**
```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <configuration>
        <argLine>-Djava.library.path=${project.basedir}/native/build</argLine>
    </configuration>
</plugin>
```

**Gradle:**
```kotlin
tasks.withType<Test> {
    jvmArgs = listOf("-Djava.library.path=${projectDir}/native/build")
}

tasks.withType<JavaExec> {
    jvmArgs = listOf("-Djava.library.path=${projectDir}/native/build")
}
```

### Option 3: Bundled in JAR (Automatic)

The Maven build automatically bundles native libraries from `native/build/` into the JAR. The SDK extracts them to a temp directory at runtime.

To verify bundled libraries:
```bash
jar tf quac100-1.0.0.jar | grep native
```

### Option 4: Working Directory

Place native libraries in the application's working directory:

```
your-app/
├── your-app.jar
├── quac100_jni.dll     (Windows)
├── quac100.dll
├── libquac100_jni.so   (Linux)
├── libquac100.so
└── ...
```

---

## IDE Configuration

### IntelliJ IDEA

1. **Add JAR Dependency:**
   - File → Project Structure → Libraries
   - Click + → Java → Select `quac100-1.0.0.jar`
   - Apply

2. **Configure Native Library Path:**
   - Run → Edit Configurations
   - Select your run configuration
   - VM Options: `-Djava.library.path=/path/to/native/libs`

3. **For Maven Projects:**
   - IntelliJ automatically handles dependencies from `pom.xml`
   - Configure run configuration VM options as above

### Eclipse

1. **Add JAR Dependency:**
   - Right-click project → Build Path → Configure Build Path
   - Libraries tab → Add External JARs
   - Select `quac100-1.0.0.jar`

2. **Configure Native Library Path:**
   - Expand the JAR in the Libraries tab
   - Select "Native library location"
   - Edit → External Folder → Select native library directory

3. **Alternative - Run Configuration:**
   - Run → Run Configurations
   - Select your application
   - Arguments tab → VM arguments: `-Djava.library.path=/path/to/native/libs`

### VS Code

1. **Add to `settings.json`:**
   ```json
   {
       "java.project.referencedLibraries": [
           "libs/**/*.jar"
       ]
   }
   ```

2. **Configure `launch.json`:**
   ```json
   {
       "configurations": [
           {
               "type": "java",
               "name": "Launch App",
               "request": "launch",
               "mainClass": "com.example.YourApp",
               "vmArgs": "-Djava.library.path=${workspaceFolder}/native/build"
           }
       ]
   }
   ```

### NetBeans

1. **Add JAR:**
   - Right-click Libraries → Add JAR/Folder
   - Select `quac100-1.0.0.jar`

2. **Configure VM Options:**
   - Right-click project → Properties
   - Run → VM Options: `-Djava.library.path=/path/to/native/libs`

---

## Application Packaging

### Fat JAR with Maven Shade Plugin

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-shade-plugin</artifactId>
    <version>3.5.1</version>
    <executions>
        <execution>
            <phase>package</phase>
            <goals>
                <goal>shade</goal>
            </goals>
            <configuration>
                <transformers>
                    <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                        <mainClass>com.example.YourApp</mainClass>
                    </transformer>
                </transformers>
            </configuration>
        </execution>
    </executions>
</plugin>
```

### Spring Boot Application

```xml
<dependency>
    <groupId>com.dyber</groupId>
    <artifactId>quac100</artifactId>
    <version>1.0.0</version>
</dependency>
```

Configure native library in `application.properties`:
```properties
# Set this in startup script instead
# java -Djava.library.path=./native -jar app.jar
```

### Docker Deployment

```dockerfile
FROM eclipse-temurin:17-jre

# Copy native libraries
COPY native/build/*.so /usr/local/lib/
RUN ldconfig

# Copy application
COPY target/your-app.jar /app/app.jar

WORKDIR /app
ENTRYPOINT ["java", "-jar", "app.jar"]
```

---

## Troubleshooting

### UnsatisfiedLinkError: no quac100_jni in java.library.path

**Cause:** Native library not found.

**Solutions:**
1. Check library path:
   ```java
   System.out.println(System.getProperty("java.library.path"));
   ```
2. Verify library exists and has correct name
3. Check library architecture matches JVM (both 64-bit or both 32-bit)
4. On Windows, ensure Visual C++ Redistributable is installed

### UnsatisfiedLinkError: dependent libraries not found

**Cause:** quac100_jni depends on quac100 which isn't found.

**Solution:** Ensure both libraries are in the same directory or in the library path.

### ClassNotFoundException: com.dyber.quac100.Library

**Cause:** JAR not in classpath.

**Solution:** Verify the JAR is added to build path/dependencies.

### Error: Module not found

**Cause:** Java 9+ module system conflict.

**Solution:** Add to module-info.java:
```java
requires com.dyber.quac100;
```

Or run with:
```bash
java --add-opens java.base/java.lang=ALL-UNNAMED -jar app.jar
```

### Simulation Mode for Testing

If you don't have hardware available:

```java
Library lib = Library.getInstance(Library.FLAG_SIMULATION);
```

---

## Version Compatibility

| SDK Version | Java Version | C Library Version |
|-------------|--------------|-------------------|
| 1.0.x       | 11+          | 1.0.x             |

---

## Support

- **Documentation:** https://docs.dyber.io/quac100/java
- **API Reference:** https://docs.dyber.io/quac100/java/api
- **Issues:** https://github.com/dyber-inc/quantacore-sdk/issues
- **Email:** support@dyber.io

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.