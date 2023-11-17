package co.edu.icesi;



import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.util.Objects;
import java.util.ResourceBundle;

public class ClientController {

    private Client client;

    private boolean lightsAreOut;


    public void initialize() {

        try {
            client = new Client(new Socket("localhost", 5130));
            establishConnection();
        } catch (IOException e) {
            System.out.println("Error creating the client.");
            e.printStackTrace();
        }

        client.receiveMessageFromServer();
    }

    private void establishConnection(){
        client.sendMessageToServer("SYN " + client.getPublicKey());
    }

    void sendMessage(String messageToSend) {
        if (!messageToSend.isEmpty()) {
            client.sendMessageToServer(messageToSend);
        }
    }

    public static void showMessage(String messageFromServer) {
        System.out.println("Message from server: " + messageFromServer);
    }

    public Thread getListenerThread() {
        return client.getListenerThread();
    }

    public void closeEverything() {
        client.closeEverything( client.getSocket(), client.getBufferedReader(), client.getBufferedWriter());
    }
}
