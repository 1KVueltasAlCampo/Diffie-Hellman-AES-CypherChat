package co.edu.icesi;


import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

public class Server {

    private ServerSocket serverSocket;
    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private Thread listenerThread;
    private DiffieHellman diffieHellman;

    public Server(ServerSocket serverSocket) throws IOException {
        this.serverSocket = serverSocket;
        this.socket = serverSocket.accept();
        this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
        this.diffieHellman = new DiffieHellman();

        diffieHellman.generateKeys();

        System.out.println("Server is up and running at " + serverSocket.getInetAddress().getHostAddress() + ":" + serverSocket.getLocalPort());
    }

    /**
     * Listens for incoming messages from a client, decrypts them using Diffie-Hellman
     * key exchange, and displays them in a message bubble.
     *
     * @param messagesVB It is a VBox object that represents a container in JavaFX, used to display
     * messages received from the client in the user interface.
     */
    public void receiveMessageFromClient() {
        listenerThread = new Thread(() -> {
            System.out.println("Listening for client incoming messages...");
            while (socket.isConnected()) {
                try {
                    String messageFromClient = bufferedReader.readLine();
                    if(messageFromClient.contains("SYN ")){
                        diffieHellman.receivePublicKeyFrom(messageFromClient.replaceAll("SYN ", ""));
                        establishConnection();
                    } else {
                        String decryptedMessage = diffieHellman.decryptMessage(messageFromClient);
                        ServerController.showMessage(decryptedMessage);
                    }
                } catch (IOException ioe) {
                    System.out.println("Error receiving message from client.");
                    closeEverything(serverSocket, socket, bufferedReader, bufferedWriter);
                    ioe.printStackTrace();
                    break;
                }
            }
        });

        listenerThread.start();
    }

    /**
     * Establishes a connection by sending a message to the client containing a
     * Diffie-Hellman public key encoded in Base64.
     */
    private void establishConnection(){
        sendMessageToClient("SYN/ACK " + Base64.getEncoder().encodeToString(diffieHellman.getPublicKey().getEncoded()));
    }

    /**
     * Sends an encrypted message to a client using a Diffie-Hellman key exchange
     * protocol.
     *
     * @param messageToSend A string message that is to be sent to the client.
     */
    public void sendMessageToClient(String messageToSend) {
        try {
            String encryptedMsg = messageToSend;
            if(!messageToSend.contains("SYN/ACK ")){
                encryptedMsg = new String(diffieHellman.encryptMessage(messageToSend));
            }
            bufferedWriter.write(encryptedMsg);
            bufferedWriter.newLine();
            bufferedWriter.flush();
        } catch (IOException ioe) {
            System.out.println("Error sending message to the client.");
            ioe.printStackTrace();
            closeEverything(serverSocket, socket, bufferedReader, bufferedWriter);
        }
        System.out.println("Message sent to client");
    }

    public void closeEverything (ServerSocket serverSocket, Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        try {
            if (bufferedReader != null){
                bufferedReader.close();
            }
            if (bufferedWriter != null){
                bufferedWriter.close();
            }
            if (socket != null){
                socket.close();
            }
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public Thread getListenerThread() {
        return listenerThread;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }

    public Socket getSocket() {
        return socket;
    }

    public BufferedReader getBufferedReader() {
        return bufferedReader;
    }

    public BufferedWriter getBufferedWriter() {
        return bufferedWriter;
    }
}
