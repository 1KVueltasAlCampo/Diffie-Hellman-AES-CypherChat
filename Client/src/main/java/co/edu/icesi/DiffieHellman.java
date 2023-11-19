package co.edu.icesi;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

    public String encryptMessage(String plainText) {
        try {
            System.out.println("Yo encripto, uso la secretKey: " + new String(secretKey));

            // Generar un IV (Vector de Inicialización) aleatorio
            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);

            // Aplicar relleno al mensaje original para que su longitud sea múltiplo de 16
            int blockSize = 16;
            int padding = blockSize - (plainText.length() % blockSize);
            StringBuilder paddedText = new StringBuilder(plainText);
            for (int i = 0; i < padding; i++) {
                paddedText.append((char) padding);
            }
            plainText = paddedText.toString();

            // Crear una instancia de la clave secreta utilizando la clave compartida
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");

            // Inicializar el cifrado en modo cifrado con la clave y el IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

            // Cifrar el mensaje
            byte[] encryptedMessageBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Combinar el IV y los datos cifrados
            byte[] combined = new byte[iv.length + encryptedMessageBytes.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encryptedMessageBytes, 0, combined, iv.length, encryptedMessageBytes.length);

            // Codificar a Base64 para obtener una representación de texto del mensaje cifrado
            return Base64.getEncoder().encodeToString(combined);
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


    public String decryptMessage(String encryptedMessage) {
        try {
            System.out.println("Yo desencripto, uso la secretKey: " + new String(secretKey));
            byte[] encryptedData = Base64.getDecoder().decode(encryptedMessage);

            byte[] iv = new byte[16]; // Tamaño del vector de inicialización (IV) utilizado en AES/CBC/PKCS5Padding

            // Extraer el IV del mensaje cifrado
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            // Crear una instancia de la clave secreta utilizando la clave compartida
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");

            // Inicializar el cifrado en modo descifrado con la clave y el IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            // Descifrar el mensaje
            byte[] decryptedMessageBytes = cipher.doFinal(encryptedData, iv.length, encryptedData.length - iv.length);

            // Quitar el relleno
            int padding = (int) decryptedMessageBytes[decryptedMessageBytes.length - 1];
            String decryptedMessage = new String(Arrays.copyOfRange(decryptedMessageBytes, 0, decryptedMessageBytes.length - padding), StandardCharsets.UTF_8);

            return decryptedMessage;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /** Auxiliary method that parses a public key in string form into a PublicKey object.
     * @param publicKey The string representation of the public key in Base64.
     * @return A corresponding PublicKey object containing the parse public key. */
    private PublicKey parsePublicKey(String publicKey){
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
