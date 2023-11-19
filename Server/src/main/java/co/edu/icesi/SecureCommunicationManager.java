package co.edu.icesi;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * The SecureCommunicationManager class implements the Diffie-Hellman key exchange protocol
 * for secure communication and provides methods for encrypting and decrypting messages.
 */
public class SecureCommunicationManager {
    private static final String ALGORITHM_DH = "DH";
    private static final String ALGORITHM_AES = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 1024;
    private static final int SECRET_KEY_SIZE = 32;

    private PrivateKey privateKey;
    private PublicKey ownPublicKey;
    private PublicKey receivedPublicKey;
    private byte[] secretKey;

    /**
     * Encrypts the given plain text message using the shared secret key.
     *
     * @param plainText The message to be encrypted.
     * @return The Base64-encoded encrypted message.
     */
    public String encryptAndEncodeMessage(String plainText) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] initializationVector = new byte[16];
            random.nextBytes(initializationVector);

            int blockSize = 16;
            int padding = blockSize - (plainText.length() % blockSize);
            StringBuilder paddedText = new StringBuilder(plainText);
            for (int i = 0; i < padding; i++) {
                paddedText.append((char) padding);
            }
            plainText = paddedText.toString();

            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, ALGORITHM_AES);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(initializationVector));

            byte[] encryptedMessageBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[initializationVector.length + encryptedMessageBytes.length];
            System.arraycopy(initializationVector, 0, combined, 0, initializationVector.length);
            System.arraycopy(encryptedMessageBytes, 0, combined, initializationVector.length, encryptedMessageBytes.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypts the given Base64-encoded encrypted message using the shared secret key.
     *
     * @param encryptedMessage The Base64-encoded encrypted message.
     * @return The decrypted message.
     */
    public String decodeAndDecryptMessage(String encryptedMessage) {
        if(encryptedMessage.contains("ACK ")){
            return encryptedMessage;
        }
        try {
            byte[] encryptedData = Base64.getDecoder().decode(encryptedMessage);

            byte[] initializationVector = new byte[16];

            System.arraycopy(encryptedData, 0, initializationVector, 0, initializationVector.length);

            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, ALGORITHM_AES);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(initializationVector));

            byte[] decryptedMessageBytes = cipher.doFinal(encryptedData, initializationVector.length, encryptedData.length - initializationVector.length);

            int padding = (int) decryptedMessageBytes[decryptedMessageBytes.length - 1];
            String decryptedMessage = new String(Arrays.copyOfRange(decryptedMessageBytes, 0, decryptedMessageBytes.length - padding), StandardCharsets.UTF_8);

            return decryptedMessage;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Generates the shared secret key using the received public key.
     */
    public void generateSharedSecretKey() {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(ALGORITHM_DH);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();

            byte[] secretKeyBytes = new byte[SECRET_KEY_SIZE];
            System.arraycopy(sharedSecret, 0, secretKeyBytes, 0, Math.min(sharedSecret.length, secretKeyBytes.length));
            secretKey = secretKeyBytes;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates the public and private key pair for Diffie-Hellman key exchange.
     */
    public void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_DH);
            keyPairGenerator.initialize(KEY_SIZE);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            ownPublicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private PublicKey parsePublicKeyFromString(String publicKeyString) {
        PublicKey parsedPublicKey = null;
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_DH);
            parsedPublicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return parsedPublicKey;
    }

    /**
     * Receives a public key from another party and generates the shared secret key.
     *
     * @param publicKeyString The Base64-encoded public key received from another party.
     * @throws IOException If there is an issue with reading the public key.
     */
    public void receivePublicKeyFromOtherParty(String publicKeyString) throws IOException {
        receivedPublicKey = parsePublicKeyFromString(publicKeyString);
        generateSharedSecretKey();
    }

    /**
     * Gets the public key of the local party.
     *
     * @return The public key of the local party.
     */
    public PublicKey getOwnPublicKey() {
        return ownPublicKey;
    }
}
