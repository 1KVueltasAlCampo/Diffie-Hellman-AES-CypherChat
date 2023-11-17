package co.edu.icesi;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.*;
import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** This class is used as a container for all methods related to the solution's Diffie-Hellman implementation.
 * */
public class DiffieHellman {

    private PrivateKey privateKey;
    private PublicKey  publicKey;
    private PublicKey  receivedPublicKey;
    private byte[] secretKey;

    /** Converts a plain text message into an encrypted byte array using the Diffie-Hellman elliptic curve method.
     * @param message The raw plain text message that's being sent.
     * @return A byte array containing a leading 16 byte initialization vector and the encrypted message.
     * */
    public byte[] encryptMessage(String message) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            byte[] iv = generateIV();

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] encryptedMessage = cipher.doFinal(message.getBytes());

            System.out.println("Encrypted " + new String (encryptedMessage));

            byte[] encryptedData = new byte[iv.length + encryptedMessage.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(encryptedMessage, 0, encryptedData, iv.length, encryptedMessage.length);

            return encryptedData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /** This is an auxiliary method that generates an IV from SecureRandom#nextBytes().
     * @return The initialization vector.
     * */
    private byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }

    /** Method used to initialize the common secret key that will be used during the exchange.
     * It runs right after the instance receives the remote public key.
     * */
    public void generateCommonSecretKey() {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            byte[] sharedSecret = keyAgreement.generateSecret();

            byte[] secretKeyBytes = new byte[32];
            System.arraycopy(sharedSecret, 0, secretKeyBytes, 0, Math.min(sharedSecret.length, secretKeyBytes.length));
            secretKey = secretKeyBytes;


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /** Generates the public and private keys to be used in the exchange by the local instance. */
    /** Generates the public and private keys to be used in the exchange by the local instance. */
    public void generateKeys() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(1024);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            publicKey  = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /** @return The public key of the instance as a PublicKey object. */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /** Takes an encrypted message and decrypts it using the provided common secret and the keys used during the Diffie-Hellman algorithm.
     * It also visibly shows the connection is secure by sending an "ACK" message, as a final acknowledgement of the client and the server have received each other's keys.
     * @param message The encrypted data containing the initialization vector and the encrypted message itself.
     * @return The decrypted message sent from the remote instance. */
    public String decryptMessage(String message) {
        if (message.contains("ACK ")){
            return message;
        }
        try {
            System.out.println(message);
            byte[] messageArray = message.getBytes();
            byte[] iv = Arrays.copyOfRange(messageArray, 0, 16);
            byte[] encryptedMessage = Arrays.copyOfRange(messageArray, 16, messageArray.length);


            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            return new String(cipher.doFinal(encryptedMessage));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /** Auxiliary method that parses a public key in string form into a PublicKey object.
     * @param publicKey The string representation of the public key in Base64.
     * @return A corresponding PublicKey object containing the parse public key. */
    private PublicKey parsePublicKey(String publicKey) {
        PublicKey pubKey = null;
        try {
            byte[] publicBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            pubKey = keyFactory.generatePublic(keySpec);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return pubKey;
    }

    /** Receives the remote public key and instances it as a PublicKey object within the local instance. It then generates the common secret key to be used.
     * @param publicKey The string representation of the remote public key sent over by the remote instance during the exchange.
     * */
    public void receivePublicKeyFrom(String publicKey) throws IOException {
        receivedPublicKey = parsePublicKey(publicKey);
        generateCommonSecretKey();
    }
}
