package co.edu.icesi;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

/**
 * The SecureServer class represents a server that uses the Diffie-Hellman key exchange
 * protocol for secure communication with clients.
 */
public class SecureServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private BufferedReader clientBufferedReader;
    private BufferedWriter clientBufferedWriter;
    private Thread listenerThread;
    private SecureCommunicationManager secureCommManager;

    /**
     * Constructs a SecureServer object with the specified ServerSocket.
     *
     * @param serverSocket The ServerSocket to accept client connections.
     * @throws IOException If an I/O error occurs while accepting the client connection.
     */
    public SecureServer(ServerSocket serverSocket) throws IOException {
        this.serverSocket = serverSocket;
        this.clientSocket = serverSocket.accept();
        this.clientBufferedReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        this.clientBufferedWriter = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        this.secureCommManager = new SecureCommunicationManager();

        secureCommManager.generateKeyPair();

        System.out.println("SecureServer is up and running at " + serverSocket.getInetAddress().getHostAddress() + ":" + serverSocket.getLocalPort());
    }

    /**
     * Listens for incoming messages from the client and processes them accordingly.
     */
    public void receiveMessageFromClient() {
        listenerThread = new Thread(() -> {
            System.out.println("Listening for client incoming messages...");
            while (clientSocket.isConnected()) {
                try {
                    String messageFromClient = clientBufferedReader.readLine();
                    if(messageFromClient.contains("SYN ")){
                        secureCommManager.receivePublicKeyFromOtherParty(messageFromClient.replaceAll("SYN ", ""));
                        establishConnection();
                    } else {
                        String decryptedMessage = secureCommManager.decodeAndDecryptMessage(messageFromClient);
                        ServerController.showMessage(decryptedMessage);
                    }
                } catch (IOException ioe) {
                    System.out.println("Error receiving message from client.");
                    closeConnections(serverSocket, clientSocket, clientBufferedReader, clientBufferedWriter);
                    ioe.printStackTrace();
                    break;
                }
            }
        });

        listenerThread.start();
    }

    private void establishConnection(){
        sendMessageToClient("SYN/ACK " + Base64.getEncoder().encodeToString(secureCommManager.getOwnPublicKey().getEncoded()));
    }

    /**
     * Sends a message to the connected client.
     *
     * @param messageToSend The message to be sent.
     */
    public void sendMessageToClient(String messageToSend) {
        try {
            String encryptedMsg = messageToSend;
            if(!messageToSend.contains("SYN/ACK ")){
                encryptedMsg = new String(secureCommManager.encryptAndEncodeMessage(messageToSend));
            }
            clientBufferedWriter.write(encryptedMsg);
            clientBufferedWriter.newLine();
            clientBufferedWriter.flush();
        } catch (IOException ioe) {
            System.out.println("Error sending message to the client.");
            ioe.printStackTrace();
            closeConnections(serverSocket, clientSocket, clientBufferedReader, clientBufferedWriter);
        }
        System.out.println("Message sent to client");
    }

    /**
     * Closes all the open connections including the ServerSocket, Socket, BufferedReader, and BufferedWriter.
     *
     * @param serverSocket The ServerSocket to be closed.
     * @param clientSocket The Socket to be closed.
     * @param clientBufferedReader The BufferedReader to be closed.
     * @param clientBufferedWriter The BufferedWriter to be closed.
     */
    public void closeConnections(ServerSocket serverSocket, Socket clientSocket, BufferedReader clientBufferedReader, BufferedWriter clientBufferedWriter) {
        try {
            if (clientBufferedReader != null) clientBufferedReader.close();
            if (clientBufferedWriter != null) clientBufferedWriter.close();
            if (clientSocket != null) clientSocket.close();
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Gets the listener thread associated with this SecureServer.
     *
     * @return The listener thread.
     */
    public Thread getListenerThread() {
        return listenerThread;
    }

    /**
     * Gets the ServerSocket associated with this SecureServer.
     *
     * @return The ServerSocket.
     */
    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    /**
     * Gets the Socket associated with this SecureServer.
     *
     * @return The Socket.
     */
    public Socket getClientSocket() {
        return clientSocket;
    }

    /**
     * Gets the BufferedReader associated with this SecureServer.
     *
     * @return The BufferedReader.
     */
    public BufferedReader getClientBufferedReader() {
        return clientBufferedReader;
    }

    /**
     * Gets the BufferedWriter associated with this SecureServer.
     *
     * @return The BufferedWriter.
     */
    public BufferedWriter getClientBufferedWriter() {
        return clientBufferedWriter;
    }
}
