import java.net.*;
import java.io.*;

public class Server {
    public static void main(String[] args) throws IOException{

        if(args.length!=1){
            System.err.println("Usage: java Server <port number>");
            System.exit(1);
        }
        int portNumber = Integer.parseInt(args[0]);

        try(
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                ){
            String inputLine, outputLine;

            SiriProtocol sp = new SiriProtocol();
        }
    }
}
