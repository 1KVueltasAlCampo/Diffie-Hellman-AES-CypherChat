package co.edu.icesi;


import java.net.URL;
import java.util.Scanner;

public class Main {



    public static void main(String[] args) {
        ClientController clientController = new ClientController();
        clientController.initialize();
        Scanner scanner = new Scanner(System.in);
        do{
            String input = scanner.nextLine();
            if(input.equals("exit")){
                clientController.closeEverything();
                System.exit(0);
            }
            else{
                clientController.sendMessage(input);
            }
        }
        while (true);
    }

}
