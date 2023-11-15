package co.edu.icesi;


import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Client {
    private Socket clientSocket;
    private BufferedReader reader;
    private BufferedWriter writer;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey receivedPublicKey;
    private byte[] secretKey;
    private String secretMessage;
    private Thread listenerThread;
    private DiffieHellman diffieHellman;

    public Client(Socket clientSocket) throws IOException {
        this.clientSocket = clientSocket;
        this.reader = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
        this.writer = new BufferedWriter(new OutputStreamWriter(this.clientSocket.getOutputStream()));
        this.diffieHellman = new DiffieHellman();

        diffieHellman.generateKeys();

        System.out.println("Connected to server at " + clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getLocalPort());
    }

    public void receiveMessageFromServer(VBox messagesVBox) {
        System.out.println("Listening for server incoming messages...");
        listenerThread = new Thread(() -> {
            while (clientSocket.isConnected()) {
                try {
                    String messageFromServer = reader.readLine();
                    if (messageFromServer.contains("SYN/ACK ")) {
                        diffieHellman.receivePublicKeyFrom(messageFromServer.replaceAll("SYN/ACK ", ""));
                        sendMessageToServer("ACK ");
                    } else {
                        String decryptedMessage = diffieHellman.decryptMessage(messageFromServer);
                        ClientController.addBubble(decryptedMessage, messagesVBox);
                    }
                } catch (IOException ioe) {
                    System.out.println("Error receiving message from server.");
                    ioe.printStackTrace();
                    break;
                }
            }
        });

        listenerThread.start();
    }

    public String getPublicKeyBase64() {
        return Base64.getEncoder().encodeToString(diffieHellman.getPublicKey().getEncoded());
    }

    public void sendMessageToServer(String messageToSend) {
        try {
            String encryptedMsg = messageToSend;
            if (!messageToSend.contains("SYN ") && !messageToSend.contains("ACK ")) {
                encryptedMsg = new String(diffieHellman.encryptMessage(messageToSend));
            }
            System.out.println(encryptedMsg);
            writer.write(encryptedMsg);
            writer.newLine();
            writer.flush();
        } catch (IOException ioe) {
            System.out.println("Error sending message to the server.");
            ioe.printStackTrace();
            closeResources();
        }
        System.out.println("Message sent to server");
    }

    public void closeResources() {
        try {
            if (reader != null) reader.close();
            if (writer != null) writer.close();
            if (clientSocket != null) clientSocket.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public Thread getListenerThread() {
        return listenerThread;
    }

    public Socket getClientSocket() {
        return clientSocket;
    }

    public BufferedReader getReader() {
        return reader;
    }

    public BufferedWriter getWriter() {
        return writer;
    }
}
