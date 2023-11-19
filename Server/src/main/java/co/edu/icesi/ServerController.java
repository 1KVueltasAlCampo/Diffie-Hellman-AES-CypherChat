package co.edu.icesi;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * The ServerController class manages the communication and interactions of the server in the secure communication system.
 */
public class ServerController {

    private SecureServer server;

    private boolean lightsAreOut;

    /**
     * Initializes the server by creating a SecureServer instance and preparing to receive messages from the client.
     */
    public void initialize() {
        try {
            server = new SecureServer(new ServerSocket(5130));
        } catch (IOException e) {
            System.out.println("Error creating the server.");
            e.printStackTrace();
        }

        // Start listening for messages from the client
        server.receiveMessageFromClient();
    }

    /**
     * Sends a message to the client, if the message is not empty.
     *
     * @param messageToSend The message to be sent.
     */
    void sendMessage(String messageToSend) {
        if (!messageToSend.isEmpty()) {
            server.sendMessageToClient(messageToSend);
        }
    }

    /**
     * Displays a message received from the client.
     *
     * @param messageFromClient The message received from the client.
     */
    public static void showMessage(String messageFromClient) {
        System.out.println("Message from client: " + messageFromClient);
    }

    /**
     * Gets the listener thread associated with the server.
     *
     * @return The listener thread.
     */
    public Thread getListenerThread() {
        return server.getListenerThread();
    }

    /**
     * Closes all open connections associated with the server.
     */
    public void closeEverything() {
        server.closeConnections(server.getServerSocket(), server.getClientSocket(), server.getClientBufferedReader(), server.getClientBufferedWriter());
    }
}