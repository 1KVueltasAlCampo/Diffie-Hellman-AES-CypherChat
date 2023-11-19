package co.edu.icesi;

import java.io.IOException;
import java.net.Socket;

/**
 * The ClientController class manages the communication and interactions of the client in the secure communication system.
 */
public class ClientController {

    private SecureClient client;

    /**
     * Initializes the client by creating a SecureClient instance and establishing a connection with the server.
     */
    public void initialize() {
        try {
            client = new SecureClient(new Socket("localhost", 5130));
            establishConnection();
        } catch (IOException e) {
            System.out.println("Error creating the client.");
            e.printStackTrace();
        }

        // Start listening for messages from the server
        client.receiveMessageFromServer();
    }

    /**
     * Establishes a connection with the server by sending a synchronization message with the client's public key.
     */
    private void establishConnection(){
        client.sendMessageToServer("SYN " + client.getEncodedPublicKey());
    }

    /**
     * Sends a message to the server, if the message is not empty.
     *
     * @param messageToSend The message to be sent.
     */
    void sendMessage(String messageToSend) {
        if (!messageToSend.isEmpty()) {
            client.sendMessageToServer(messageToSend);
        }
    }

    /**
     * Displays a message received from the server.
     *
     * @param messageFromServer The message received from the server.
     */
    public static void showMessage(String messageFromServer) {
        System.out.println("Message from server: " + messageFromServer);
    }

    /**
     * Gets the listener thread associated with the client.
     *
     * @return The listener thread.
     */
    public Thread getListenerThread() {
        return client.getListenerThread();
    }

    /**
     * Closes all open connections associated with the client.
     */
    public void closeEverything() {
        client.closeConnections(client.getServerSocket(), client.getServerBufferedReader(), client.getServerBufferedWriter());
    }
}
