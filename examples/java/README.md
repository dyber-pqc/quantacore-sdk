# QUAC 100 Java Examples

Java bindings and examples for the QUAC 100 post-quantum cryptographic accelerator.

## Requirements

- Java 17+
- QUAC 100 SDK installed
- quac100.jar in classpath

## Installation

Maven:
```xml
<dependency>
    <groupId>com.dyber</groupId>
    <artifactId>quac100</artifactId>
    <version>1.0.0</version>
</dependency>
```

Gradle:
```groovy
implementation 'com.dyber:quac100:1.0.0'
```

## Examples

| File | Description |
|------|-------------|
| `HelloQUAC.java` | Basic initialization and random generation |
| `KEMDemo.java` | ML-KEM key exchange demonstration |
| `SignDemo.java` | ML-DSA digital signature demonstration |
| `SecureSession.java` | Secure session establishment example |

## Quick Start

```java
import com.dyber.quac100.*;

public class QuickStart {
    public static void main(String[] args) {
        try (Context ctx = new Context();
             Device device = ctx.openDevice(0)) {
            
            // Generate random bytes
            byte[] random = device.random(32);
            System.out.println("Random: " + toHex(random));
            
            // ML-KEM key exchange
            KeyPair kp = device.kemKeygen(Algorithm.ML_KEM_768);
            EncapsResult er = device.kemEncaps(Algorithm.ML_KEM_768, kp.publicKey);
            byte[] ss = device.kemDecaps(Algorithm.ML_KEM_768, er.ciphertext, kp.secretKey);
            
            System.out.println("Key exchange complete!");
            
        } catch (QUACException e) {
            e.printStackTrace();
        }
    }
}
```

## Building Examples

```bash
javac -cp quac100.jar:. HelloQUAC.java
java -cp quac100.jar:. HelloQUAC
```

Or with Maven:
```bash
mvn compile exec:java -Dexec.mainClass="HelloQUAC"
```

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.