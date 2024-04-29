import java.net.*;
import java.io.*;
import java.security.*;

public class KDC {

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }



    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        //creating keypair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //storing public key in file
        System.out.println("creating publicKey file");
        ObjectOutputStream publicStream = new ObjectOutputStream(new FileOutputStream("KDCPublicKey.xx"));
        publicStream.writeObject(publicKey);
        publicStream.close();

        //storing private key in file
        System.out.println("creating privateKey file");
        ObjectOutputStream privateStream = new ObjectOutputStream(new FileOutputStream("KDCPrivateKey.xx"));//no need to store in file, just doing it for convenience
        privateStream.writeObject(privateKey);
        privateStream.close();



        int KDCPort = 4888;
        boolean listening = true;

        try(ServerSocket serverSocket = new ServerSocket(KDCPort)){
            while(listening){
                new KDCThread(serverSocket.accept()).start();
            }
        } catch(IOException e){
            System.err.println(("Could not listen on port " + KDCPort));
            System.exit(-1);
        }
    }
}

/*potential vulnerability:

an attacker can intercept the first message going to KDC in Phase 2
no verification is done here
so, an attacker can easily replay the message from KDC to A and KDC to B
now, there is a vulnerability in using the same shared session key between A and B that is
from an old session.

in order to solve this, we can encrypt IDa and IDb as well as include an encrypted nonce value
that are all encrypted using the session key generated in phase 1
doing so will ensure only A and KDC can understand those messages.

 */
























//import java.io.*;
//import java.net.*;
//import java.security.*;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.KeySpec;
//import java.util.*;
//import javax.crypto.*;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.PBEKeySpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.util.Base64;
//
//public class KDC {
//
//    public static void main(String[] args) throws Exception {
//        //String localHost = "127.0.0.1";
//        String ID = "alice";
//        int portNum = 4999;
//        String userInput, encrypted, incoming;
//        String[] received = new String[3];
//        String checkEncode = "encrypted~";
//        int index = 0;
//        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
//        DES des = new DES(key);
//        System.out.println("creating SecretKey.txt");
//        System.out.println("THIS IS A KEY: " + key.toString());
//        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("SecretKey.xx"));
//        outputStream.writeObject(key);
//        outputStream.close();
//
//        try (
//                Socket KDCsocket = new Socket("localhost", portNum);
//                PrintWriter out = new PrintWriter(KDCsocket.getOutputStream(), true);
//                BufferedReader in = new BufferedReader(new InputStreamReader(KDCsocket.getInputStream()));
//                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
//        ) {
//
//                //KDC receives
//            incoming = in.readLine();
//
//            while (!Objects.equals(userInput = stdIn.readLine(), "stop")) {
//                out.println(userInput); //send ID and Nonce
//            }
//            out.println("stop");
//            while (!Objects.equals(incoming = in.readLine(), "stop")) {
//                received[index] = incoming;
//                index++;
//            }
//            String join = String.join(" || ", received);
//            System.out.println("Received Message 2 encoded: " + join);
//            //received[] contains all decrypted data
//            //received[0] == N_b
//            //received[1] == ID_b
//            //received[2] == N_a
//            String encIDA = des.encrypt(ID);
//            String encNB = des.encrypt(received[0]);
//            String bob = des.decrypt(received[1]);
//            String myNonce = des.decrypt(received[2]);
//            System.out.println("Received Message 2 decoded: " + received[0] + " || " + bob + " || " + myNonce);
//            out.println(encIDA);
//            out.println(encNB);
//            out.println("stop");
//
//
//        } catch (UnknownHostException e) {
//            System.err.println("Don't know about host " + ID);
//            System.exit(1);
//        } catch (IOException e) {
//            System.err.println("Couldn't get I/O for the connection to " + ID);
//            System.exit(1);
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//}