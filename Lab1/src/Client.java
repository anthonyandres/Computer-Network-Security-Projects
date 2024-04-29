import java.io.*;
import java.net.*;

public class Client {
    public static void main(String[] args) throws IOException{
        if (args.length != 2) {
            System.err.println("Usage: java EchoClient <host name> <port number>");
            System.exit(1);
        }

        //host name and portNumber are obtained from command line
        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);

        try(
                Socket spSocket = new Socket(hostName, portNumber);
                PrintWriter out = new PrintWriter(spSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(spSocket.getInputStream()))
                ){
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            String fromServer;
            String fromUser;

            while((fromServer = in.readLine()) != null) {
                System.out.println("Server: " + fromServer);
                if (fromServer.equals("Bye.")) {
                    break;
                }
                fromUser = stdIn.readLine();
                if(fromUser != null){
                    System.out.println("Client: " + fromUser);
                    out.println(fromUser);
                }
            }
        } catch(UnknownHostException e){
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch(IOException e){
            System.err.println("Couldn't get I/O for the connection to " + hostName);
            System.exit(1);
        }
    }
}
