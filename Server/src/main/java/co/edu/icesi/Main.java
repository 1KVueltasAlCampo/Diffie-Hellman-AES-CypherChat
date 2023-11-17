package co.edu.icesi;


import java.net.URL;
import java.util.Scanner;

public class Main {



    public static void main(String[] args) {
        ServerController serverController = new ServerController();
        Scanner scanner = new Scanner(System.in);
        serverController.initialize();
        do{
            System.out.println("Waiting for input...");
            String input = scanner.nextLine();
            if(input.equals("exit")){
                serverController.closeEverything();
                System.exit(0);
            }
            else{
                serverController.sendMessage(input);
            }
        }
        while (true);
    }

}
