package co.edu.icesi;

import java.io.IOException;
import java.net.ServerSocket;

public class ServerController{
    private Server server;

    private boolean lightsAreOut;
    public void initialize() {
        try {
            server = new Server(new ServerSocket(5130));
        } catch (IOException e) {
            System.out.println("Error creating the server.");
            e.printStackTrace();
        }


        server.receiveMessageFromClient();
    }

    void sendMessage(String messageToSend) {
        if (!messageToSend.isEmpty()) {
            server.sendMessageToClient(messageToSend);
        }
    }
    public static void showMessage(String messageFromClient) {
        System.out.println("Message from client: " + messageFromClient);
    }

    public Thread getListenerThread() {
        return server.getListenerThread();
    }

    public void closeEverything() {
        server.closeEverything( server.getServerSocket(), server.getSocket(), server.getBufferedReader(), server.getBufferedWriter());
    }
}
