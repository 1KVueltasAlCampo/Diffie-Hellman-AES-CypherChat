package co.edu.icesi;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * The DiffieHellman class implements the Diffie-Hellman key exchange protocol
 * and provides methods for encrypting and decrypting messages using the shared secret key.
 */
public class DiffieHellman {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String KEY_AGREEMENT_ALGORITHM = "DH";

    private PublicKey localPublicKey;
    private PrivateKey privateKey;
    private PublicKey remotePublicKey;
    private byte[] secretKey;

    /**
     * Generates a random Initialization Vector (IV) for encryption.
     *
     * @return A randomly generated IV.
     */
    private byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Parses a Base64-encoded public key from a string.
     *
     * @param publicKey The Base64-encoded public key string.
     * @return The parsed public key.
     */
    private PublicKey parsePublicKey(String publicKey) {
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_AGREEMENT_ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception ex) {
            // Handle exceptions or log errors if needed.
            return null;
        }
    }

    /**
     * Generates a pair of public and private keys for the local entity.
     */
    public void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_AGREEMENT_ALGORITHM);
            keyPairGenerator.initialize(1024);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            localPublicKey = keyPair.getPublic();
        } catch (Exception e) {
            // Handle exceptions or log errors if needed.
        }
    }

    /**
     * Generates a common secret key based on the local private key and the remote public key.
     */
    public void generateCommonSecretKey() {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(remotePublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();

            secretKey = Arrays.copyOf(sharedSecret, 32);

        } catch (Exception e) {
            // Handle exceptions or log errors if needed.
        }
    }

    /**
     * Receives the public key from the remote entity and generates the common secret key.
     *
     * @param remotePublicKey The Base64-encoded public key received from the remote entity.
     * @throws IOException If there is an issue parsing the public key.
     */
    public void receivePublicKeyFrom(String remotePublicKey) throws IOException {
        this.remotePublicKey = parsePublicKey(remotePublicKey);
        generateCommonSecretKey();
    }

    /**
     * Encrypts a message using the shared secret key and returns the encrypted data.
     *
     * @param message The message to be encrypted.
     * @return The encrypted message data.
     */
    public byte[] encryptMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, ALGORITHM));

            byte[] iv = generateIV();
            byte[] encryptedMessage = cipher.doFinal(message.getBytes());

            byte[] encryptedData = new byte[iv.length + encryptedMessage.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(encryptedMessage, 0, encryptedData, iv.length, encryptedMessage.length);

            return encryptedData;
        } catch (Exception e) {
            // Handle exceptions or log errors if needed.
            return null;
        }
    }

    /**
     * Decrypts an encrypted message using the shared secret key.
     *
     * @param encryptedMessage The Base64-encoded encrypted message.
     * @return The decrypted message.
     */
    public String decryptMessage(String encryptedMessage) {
        try {
            byte[] messageArray = Base64.getDecoder().decode(encryptedMessage);
            byte[] iv = Arrays.copyOfRange(messageArray, 0, 16);
            byte[] encryptedData = Arrays.copyOfRange(messageArray, 16, messageArray.length);

            SecretKeySpec keySpec = new SecretKeySpec(secretKey, ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            return new String(cipher.doFinal(encryptedData));
        } catch (Exception e) {
            // Handle exceptions or log errors if needed.
            return null;
        }
    }
}
