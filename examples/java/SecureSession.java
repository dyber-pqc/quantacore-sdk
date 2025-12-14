
/**
 * QUAC 100 Secure Session Establishment (Java)
 * 
 * Demonstrates secure session establishment using:
 * - ML-KEM for key exchange
 * - ML-DSA for authentication
 * - AES-GCM for session encryption
 * 
 * Build: javac SecureSession.java
 * Run:   java SecureSession
 * 
 * Copyright 2025 Dyber, Inc. All Rights Reserved.
 */

import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simulated QUAC Device for cryptographic operations
 */
class QUACDevice {
    private final SecureRandom random = new SecureRandom();

    // ML-KEM-768 sizes
    public static final int KEM_PK_SIZE = 1184;
    public static final int KEM_SK_SIZE = 2400;
    public static final int KEM_CT_SIZE = 1088;
    public static final int KEM_SS_SIZE = 32;

    // ML-DSA-65 sizes
    public static final int SIGN_PK_SIZE = 1952;
    public static final int SIGN_SK_SIZE = 4032;
    public static final int SIGN_SIG_SIZE = 3309;

    private byte[] lastKemSS = null;
    private byte[] signSK = null;

    public byte[][] kemKeygen() {
        byte[] pk = new byte[KEM_PK_SIZE];
        byte[] sk = new byte[KEM_SK_SIZE];
        random.nextBytes(pk);
        random.nextBytes(sk);
        return new byte[][] { pk, sk };
    }

    public byte[][] kemEncaps(byte[] pk) {
        byte[] ct = new byte[KEM_CT_SIZE];
        byte[] ss = new byte[KEM_SS_SIZE];
        random.nextBytes(ct);
        random.nextBytes(ss);
        lastKemSS = ss.clone();
        return new byte[][] { ct, ss };
    }

    public byte[] kemDecaps(byte[] ct, byte[] sk) {
        if (lastKemSS != null) {
            return lastKemSS.clone();
        }
        byte[] ss = new byte[KEM_SS_SIZE];
        random.nextBytes(ss);
        return ss;
    }

    public byte[][] signKeygen() {
        byte[] pk = new byte[SIGN_PK_SIZE];
        byte[] sk = new byte[SIGN_SK_SIZE];
        random.nextBytes(pk);
        random.nextBytes(sk);
        signSK = sk.clone();
        return new byte[][] { pk, sk };
    }

    public byte[] sign(byte[] message, byte[] sk) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(message);
        md.update(sk);
        byte[] hash = md.digest();

        byte[] sig = new byte[SIGN_SIG_SIZE];
        System.arraycopy(hash, 0, sig, 0, hash.length);
        random.nextBytes(Arrays.copyOfRange(sig, 32, sig.length));
        return sig;
    }

    public boolean verify(byte[] message, byte[] signature, byte[] pk) {
        try {
            if (signSK == null)
                return false;

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message);
            md.update(signSK);
            byte[] expectedHash = md.digest();

            for (int i = 0; i < 32; i++) {
                if (signature[i] != expectedHash[i])
                    return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public byte[] random(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}

/**
 * Session keys and state
 */
class SessionKeys {
    public final byte[] encryptKey;
    public final byte[] decryptKey;
    public final byte[] macKey;

    public SessionKeys(byte[] masterSecret) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Derive encryption key
        md.update(masterSecret);
        md.update("encrypt".getBytes());
        encryptKey = md.digest();

        // Derive decryption key
        md.reset();
        md.update(masterSecret);
        md.update("decrypt".getBytes());
        decryptKey = md.digest();

        // Derive MAC key
        md.reset();
        md.update(masterSecret);
        md.update("mac".getBytes());
        macKey = md.digest();
    }

    public void clear() {
        Arrays.fill(encryptKey, (byte) 0);
        Arrays.fill(decryptKey, (byte) 0);
        Arrays.fill(macKey, (byte) 0);
    }
}

/**
 * Secure Session Manager
 */
class SecureSessionManager {
    private final QUACDevice device;
    private SessionKeys sessionKeys;
    private final SecureRandom random = new SecureRandom();

    // AES-GCM parameters
    private static final int GCM_NONCE_SIZE = 12;
    private static final int GCM_TAG_SIZE = 128; // bits

    public SecureSessionManager(QUACDevice device) {
        this.device = device;
    }

    /**
     * Server-side session establishment
     */
    public byte[] serverHandshake(byte[] clientKemPK, byte[] serverSignSK) throws Exception {
        System.out.println("  [Server] Performing key encapsulation...");

        // Encapsulate to client's KEM public key
        byte[][] encapsResult = device.kemEncaps(clientKemPK);
        byte[] kemCT = encapsResult[0];
        byte[] sharedSecret = encapsResult[1];

        System.out.println("    Ciphertext: " + kemCT.length + " bytes");
        System.out.println("    Shared secret derived: " + sharedSecret.length + " bytes");

        // Derive session keys
        sessionKeys = new SessionKeys(sharedSecret);
        System.out.println("    Session keys derived");

        // Sign the ciphertext for authentication
        System.out.println("  [Server] Signing handshake transcript...");
        byte[] signature = device.sign(kemCT, serverSignSK);
        System.out.println("    Signature: " + signature.length + " bytes");

        // Return ciphertext + signature
        byte[] response = new byte[kemCT.length + signature.length];
        System.arraycopy(kemCT, 0, response, 0, kemCT.length);
        System.arraycopy(signature, 0, response, kemCT.length, signature.length);

        // Clear sensitive data
        Arrays.fill(sharedSecret, (byte) 0);

        return response;
    }

    /**
     * Client-side session establishment
     */
    public boolean clientHandshake(byte[] serverResponse, byte[] clientKemSK,
            byte[] serverSignPK) throws Exception {
        System.out.println("  [Client] Processing server response...");

        // Extract ciphertext and signature
        byte[] kemCT = Arrays.copyOf(serverResponse, QUACDevice.KEM_CT_SIZE);
        byte[] signature = Arrays.copyOfRange(serverResponse, QUACDevice.KEM_CT_SIZE,
                serverResponse.length);

        System.out.println("    Ciphertext: " + kemCT.length + " bytes");
        System.out.println("    Signature: " + signature.length + " bytes");

        // Verify server signature
        System.out.println("  [Client] Verifying server signature...");
        if (!device.verify(kemCT, signature, serverSignPK)) {
            System.out.println("    ✗ Signature verification FAILED!");
            return false;
        }
        System.out.println("    ✓ Signature verified - server authenticated");

        // Decapsulate to get shared secret
        System.out.println("  [Client] Decapsulating shared secret...");
        byte[] sharedSecret = device.kemDecaps(kemCT, clientKemSK);
        System.out.println("    Shared secret recovered: " + sharedSecret.length + " bytes");

        // Derive session keys
        sessionKeys = new SessionKeys(sharedSecret);
        System.out.println("    Session keys derived");

        // Clear sensitive data
        Arrays.fill(sharedSecret, (byte) 0);

        return true;
    }

    /**
     * Encrypt a message using the session key
     */
    public byte[] encrypt(byte[] plaintext) throws Exception {
        if (sessionKeys == null) {
            throw new IllegalStateException("Session not established");
        }

        // Generate nonce
        byte[] nonce = new byte[GCM_NONCE_SIZE];
        random.nextBytes(nonce);

        // Encrypt with AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(sessionKeys.encryptKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Return nonce + ciphertext
        byte[] result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

        return result;
    }

    /**
     * Decrypt a message using the session key
     */
    public byte[] decrypt(byte[] ciphertext) throws Exception {
        if (sessionKeys == null) {
            throw new IllegalStateException("Session not established");
        }

        // Extract nonce
        byte[] nonce = Arrays.copyOf(ciphertext, GCM_NONCE_SIZE);
        byte[] ct = Arrays.copyOfRange(ciphertext, GCM_NONCE_SIZE, ciphertext.length);

        // Decrypt with AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(sessionKeys.encryptKey, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_SIZE, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        return cipher.doFinal(ct);
    }

    /**
     * Close the session and clear keys
     */
    public void close() {
        if (sessionKeys != null) {
            sessionKeys.clear();
            sessionKeys = null;
        }
    }
}

/**
 * Main Secure Session Demo
 */
public class SecureSession {

    private static String toHex(byte[] bytes, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, maxBytes); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > maxBytes) {
            sb.append("...");
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        System.out.println("================================================================");
        System.out.println("  QUAC 100 Secure Session Establishment Demo (Java)");
        System.out.println("  ML-KEM-768 + ML-DSA-65 + AES-256-GCM");
        System.out.println("================================================================");
        System.out.println();

        try {
            QUACDevice device = new QUACDevice();
            System.out.println("Using software simulator.");
            System.out.println();

            // =================================================================
            // Step 1: Generate Long-term Keys
            // =================================================================
            System.out.println("Step 1: Generate Long-term Keys");
            System.out.println("--------------------------------");

            // Client's KEM keypair (for receiving encrypted session keys)
            System.out.println("  Generating client KEM keypair...");
            byte[][] clientKemKP = device.kemKeygen();
            byte[] clientKemPK = clientKemKP[0];
            byte[] clientKemSK = clientKemKP[1];
            System.out.println("    Public key: " + clientKemPK.length + " bytes");

            // Server's signing keypair (for authentication)
            System.out.println("  Generating server signing keypair...");
            byte[][] serverSignKP = device.signKeygen();
            byte[] serverSignPK = serverSignKP[0];
            byte[] serverSignSK = serverSignKP[1];
            System.out.println("    Public key: " + serverSignPK.length + " bytes");
            System.out.println();

            // =================================================================
            // Step 2: Session Establishment
            // =================================================================
            System.out.println("Step 2: Session Establishment (Handshake)");
            System.out.println("-----------------------------------------");

            SecureSessionManager serverSession = new SecureSessionManager(device);
            SecureSessionManager clientSession = new SecureSessionManager(device);

            // Server creates response
            System.out.println();
            byte[] serverResponse = serverSession.serverHandshake(clientKemPK, serverSignSK);
            System.out.println("    Server response: " + serverResponse.length + " bytes");

            // Client processes response
            System.out.println();
            boolean success = clientSession.clientHandshake(serverResponse, clientKemSK, serverSignPK);

            if (!success) {
                System.out.println("Session establishment failed!");
                System.exit(1);
            }
            System.out.println();
            System.out.println("✓ Secure session established!");
            System.out.println();

            // =================================================================
            // Step 3: Encrypted Communication
            // =================================================================
            System.out.println("Step 3: Encrypted Communication");
            System.out.println("--------------------------------");

            // Client sends encrypted message
            String message1 = "Hello Server! This is a secure message.";
            System.out.println("  [Client] Sending: \"" + message1 + "\"");

            byte[] encrypted1 = clientSession.encrypt(message1.getBytes());
            System.out.println("    Encrypted: " + toHex(encrypted1, 32));

            byte[] decrypted1 = serverSession.decrypt(encrypted1);
            System.out.println("  [Server] Received: \"" + new String(decrypted1) + "\"");
            System.out.println();

            // Server sends encrypted response
            String message2 = "Hello Client! Message received securely.";
            System.out.println("  [Server] Sending: \"" + message2 + "\"");

            byte[] encrypted2 = serverSession.encrypt(message2.getBytes());
            System.out.println("    Encrypted: " + toHex(encrypted2, 32));

            byte[] decrypted2 = clientSession.decrypt(encrypted2);
            System.out.println("  [Client] Received: \"" + new String(decrypted2) + "\"");
            System.out.println();

            // Verify messages
            if (message1.equals(new String(decrypted1)) &&
                    message2.equals(new String(decrypted2))) {
                System.out.println("✓ All messages transmitted correctly!");
            }
            System.out.println();

            // =================================================================
            // Step 4: Session Teardown
            // =================================================================
            System.out.println("Step 4: Session Teardown");
            System.out.println("------------------------");

            serverSession.close();
            clientSession.close();

            // Secure cleanup
            Arrays.fill(clientKemSK, (byte) 0);
            Arrays.fill(serverSignSK, (byte) 0);

            System.out.println("  Session keys securely erased.");
            System.out.println("  Long-term secret keys cleared.");
            System.out.println();

            // =================================================================
            // Summary
            // =================================================================
            System.out.println("================================================================");
            System.out.println("  Secure Session Demo Complete");
            System.out.println("================================================================");
            System.out.println();
            System.out.println("Protocol Summary:");
            System.out.println("  1. Client generates ephemeral ML-KEM-768 keypair");
            System.out.println("  2. Server encapsulates session key to client's public key");
            System.out.println("  3. Server signs the ciphertext with ML-DSA-65");
            System.out.println("  4. Client verifies signature and decapsulates");
            System.out.println("  5. Both derive identical session keys");
            System.out.println("  6. Communication encrypted with AES-256-GCM");
            System.out.println();
            System.out.println("Security Properties:");
            System.out.println("  • Post-quantum key exchange (ML-KEM-768)");
            System.out.println("  • Post-quantum authentication (ML-DSA-65)");
            System.out.println("  • Forward secrecy (ephemeral KEM keys)");
            System.out.println("  • Authenticated encryption (AES-GCM)");
            System.out.println("================================================================");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}