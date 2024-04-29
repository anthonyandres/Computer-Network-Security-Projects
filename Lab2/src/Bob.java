import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Objects;

public class Bob {
    static int nonce = 1 + (int) (Math.random() * 99999);
    static String bobNonce = Integer.toString(nonce);

//    public static String isolateEncryption(String encoded) {
//        int length = encoded.length();
//        char[] encodedChar = encoded.toCharArray();
//        int indexOfEncode = encoded.indexOf("~") + 1;
//        char[] iso = new char[length - indexOfEncode];
//        for (int i = 0; i < length - indexOfEncode; i++) {
//            //System.out.println(encodedChar[indexOfEncode+i]);
//            iso[i] = encodedChar[indexOfEncode + i];
//        }
//        //String iso = Arrays.copyOfRange(encoded, indexOfEncode, length);
//        String result = String.valueOf(iso);
//
//        return result;
//    }

    public static void main(String[] args) throws IOException {
        System.out.println("nonce: " + nonce);

        String ID = "bob";
        int portNumber = 4999;

        try (
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        ) {
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("SecretKey.xx"));
            SecretKey key = (SecretKey) inputStream.readObject();
            System.out.println("THIS IS A KEY: " + key.toString());
            //SecretKey key = KeyGenerator.getInstance("DES").generateKey();
            inputStream.close();

            String inputLine, outputLine, decodedMessage;
            String checkEncode = "encrypted~";

            //Initiate conversation with client
            String[] rec = new String[2]; //rec[0] is alice id, rec[1] is N_a
            String[] received = new String[2];
            int index = 0;


            while (!Objects.equals(inputLine = in.readLine(), "stop")) {
                System.out.println(inputLine);
                rec[index] = inputLine;
                index++;
            }
            System.out.println("Received Message 1: " + String.join(" || ", rec));
            //System.out.println("sending my nonce");
            out.println(bobNonce);//sending Nonce_b
            DES des = new DES(key);
            String encryptedID = des.encrypt(ID);
            //System.out.println("encryptedID: " + encryptedID);
            String encryptedNA = des.encrypt(rec[1]);
            out.println(encryptedID);//sending encrypted ID_b || N_a
            out.println(encryptedNA);
            out.println("stop");

            index = 0;
            while (!Objects.equals(inputLine = in.readLine(), "stop")) {
                received[index] = inputLine;
                index++;
            }
            String alice = des.decrypt(received[0]);
            String myNonce = des.decrypt(received[1]);
            System.out.println("Received Message 3 encoded: " + String.join(" || ", received));
            System.out.println("Received Message 3 decoded: " + alice + " || " + myNonce);

        } catch (IOException e) {
            System.out.println("Exception caught when trying to listen on port " + portNumber + " or listening for a connection");
            System.out.println(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}






























    //    public static void main(String[] args) throws IOException{
//
//        //error for more arguments than expected
//        if(args.length !=1){
//            System.err.println("Usage: java Server <port number>");
//            System.exit(1);
//        }
//
//        //userID is the first string in args (just converted to integer)
//        int userID = Integer.parseInt(args[0]);
//
//        try(
//                ServerSocket serverSocket = new ServerSocket(userID);
//                Socket clientSocket = serverSocket.accept();
//                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
//                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
//        ){
//            String inputLine, outputLine, decodedMessage, key;
//
//            //Initiate conversation with client
//            SiriProtocol sp = new SiriProtocol();
//            VigCipher cypher = new VigCipher();
//            while((inputLine = in.readLine()) != null){
//                key = cypher.createKey(inputLine,"tmu");
//                decodedMessage = cypher.decode(inputLine, key);
//                System.out.println("From client: " + inputLine + "\nDecoded: " + decodedMessage);
//                outputLine = sp.processInput(decodedMessage);
//                out.println(outputLine);
//                if(outputLine.equals("Bye.")){
//                    break;
//                }
//                System.out.println("\n\n");
//            }
//
//        }
//        catch(IOException e){
//            System.out.println("Exception caught when trying to listen on port " +userID+ " or listening for a connection");
//            System.out.println(e.getMessage());
//        }
//    }

