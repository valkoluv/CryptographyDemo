import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptographyDemo {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    // --- SYMMETRIC ENCRYPTION (AES) ---

    public static SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGen.init(128); // 128-bit key size
        return keyGen.generateKey();
    }

    public static byte[] aesEncrypt(String plainText, SecretKey key, IvParameterSpec iv) throws Exception {
        // Initializes the cipher for encryption with the key and IV
        Cipher cipher = Cipher.getInstance(AES_CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    public static String aesDecrypt(byte[] cipherText, SecretKey key, IvParameterSpec iv) throws Exception {
        // Initializes the cipher for decryption with the key and IV
        Cipher cipher = Cipher.getInstance(AES_CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] original = cipher.doFinal(cipherText);
        return new String(original, "UTF-8");
    }
    
    // --- ASYMMETRIC ENCRYPTION (RSA) ---

    public static KeyPair generateRsaKeyPair() throws Exception {
        // Generates an RSA key pair (Public and Private keys)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyGen.initialize(2048); // 2048-bit key size for security
        return keyGen.generateKeyPair();
    }

    public static byte[] rsaEncrypt(String plainText, PublicKey publicKey) throws Exception {
        // Encrypts data using the Public Key
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    public static String rsaDecrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        // Decrypts data using the Private Key
        Cipher cipher = Cipher.getInstance(RSA_CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] original = cipher.doFinal(cipherText);
        return new String(original, "UTF-8");
    }
    
    // --- DIGITAL SIGNATURE ---

    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        // Creates a signature using the Private Key (Signing)
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data.getBytes("UTF-8"));
        return signature.sign();
    }

    public static boolean verifySignature(String data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        // Verifies the signature using the Public Key
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data.getBytes("UTF-8"));
        return signature.verify(signatureBytes);
    }

    // --- MAIN LOGIC ---

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Cryptography Processes Demonstration ===");
        
        try {
            System.out.print("\nPlease enter a text string for all operations: ");
            String originalText = scanner.nextLine();

            // --- LEVEL 1: AES ---
            System.out.println("\n--- 1. SYMMETRIC ENCRYPTION (AES) ---");
            SecretKey aesKey = generateAesKey();
            // Generate a random 16-byte Initialization Vector (IV)
            byte[] ivBytes = new byte[16];
            new SecureRandom().nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            byte[] aesEncrypted = aesEncrypt(originalText, aesKey, iv);
            String aesDecrypted = aesDecrypt(aesEncrypted, aesKey, iv);

            System.out.println("🔒 AES Ciphertext (Base64): " + Base64.getEncoder().encodeToString(aesEncrypted));
            System.out.println("🔓 AES Decrypted Text: " + aesDecrypted);
            System.out.println("Result: " + (originalText.equals(aesDecrypted) ? "✅ Success" : "❌ Error"));
            
            // --- LEVEL 2: RSA ---
            System.out.println("\n--- 2. ASYMMETRIC ENCRYPTION (RSA) ---");
            KeyPair rsaKeyPair = generateRsaKeyPair();
            PublicKey publicKey = rsaKeyPair.getPublic();
            PrivateKey privateKey = rsaKeyPair.getPrivate();
            
            byte[] rsaEncrypted = rsaEncrypt(originalText, publicKey);
            String rsaDecrypted = rsaDecrypt(rsaEncrypted, privateKey);

            System.out.println("🔑 Public Key (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()).substring(0, 40) + "...");
            System.out.println("🔒 RSA Ciphertext (Base64): " + Base64.getEncoder().encodeToString(rsaEncrypted));
            System.out.println("🔓 RSA Decrypted Text: " + rsaDecrypted);
            System.out.println("Result: " + (originalText.equals(rsaDecrypted) ? "✅ Success" : "❌ Error"));

            // --- LEVEL 3: DIGITAL SIGNATURE ---
            System.out.println("\n--- 3. DIGITAL SIGNATURE (SHA256withRSA) ---");

            // Create a digital signature using the Private Key
            byte[] signatureBytes = sign(originalText, privateKey);
            String encodedSignature = Base64.getEncoder().encodeToString(signatureBytes);

            System.out.println("✍️ Digital Signature (Base64): " + encodedSignature);

            // Verification of the signature using the Public Key
            boolean isVerified = verifySignature(originalText, signatureBytes, publicKey);

            System.out.println("🔍 Signature Verification Check:");
            System.out.println("   Original Text and Signature: " + isVerified);
            
            // Attempt to tamper (should fail verification)
            String tamperedText = originalText + " (Tampered)";
            boolean isTampered = verifySignature(tamperedText, signatureBytes, publicKey);

            System.out.println("   Tampered Text and Original Signature: " + isTampered);
            System.out.println("Result: " + (isVerified && !isTampered ? "✅ Success (Signature valid, tampering detected)" : "❌ Error"));


        } catch (Exception e) {
            System.err.println("An error occurred during the cryptographic operation: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}