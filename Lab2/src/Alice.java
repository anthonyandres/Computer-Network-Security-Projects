import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/*
Alice -------------------- ID_alice || Nonce_alice -------------------> Bob
Alice <---- Nonce_bob || encrypted ID_bob || encrypted Nonce_alice ---- Bob
Alice ---------- encrypted ID_alice || encrypted Nonce_bob -----------> Bob
 */


public class Alice {

    public static String isolateEncryption(String encoded) {
        int length = encoded.length();
        char[] encodedChar = encoded.toCharArray();
        int indexOfEncode = encoded.indexOf("~") + 1;
        char[] iso = new char[length - indexOfEncode];
        for (int i = 0; i < length - indexOfEncode; i++) {
            //System.out.println(encodedChar[indexOfEncode+i]);
            iso[i] = encodedChar[indexOfEncode + i];
        }
        //String iso = Arrays.copyOfRange(encoded, indexOfEncode, length);
        String result = String.valueOf(iso);

        return result;
    }

    public static void main(String[] args) throws Exception {
        //String localHost = "127.0.0.1";
        String ID = "alice";
        int portNum = 4999;
        String userInput, encrypted, incoming;
        String[] received = new String[3];
        String checkEncode = "encrypted~";
        int index = 0;
        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        DES des = new DES(key);
        System.out.println("creating SecretKey.txt");
        System.out.println("THIS IS A KEY: " + key.toString());
        ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("SecretKey.xx"));
        outputStream.writeObject(key);
        outputStream.close();

        try (
                Socket aliceSocket = new Socket("localhost", portNum);
                PrintWriter out = new PrintWriter(aliceSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(aliceSocket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
        ) {


            while (!Objects.equals(userInput = stdIn.readLine(), "stop")) {
                out.println(userInput); //send ID and Nonce
            }
            out.println("stop");
            while (!Objects.equals(incoming = in.readLine(), "stop")) {
                received[index] = incoming;
                index++;
            }
            String join = String.join(" || ", received);
            System.out.println("Received Message 2 encoded: " + join);
            //received[] contains all decrypted data
            //received[0] == N_b
            //received[1] == ID_b
            //received[2] == N_a
            String encIDA = des.encrypt(ID);
            String encNB = des.encrypt(received[0]);
            String bob = des.decrypt(received[1]);
            String myNonce = des.decrypt(received[2]);
            System.out.println("Received Message 2 decoded: " + received[0] + " || " + bob + " || " + myNonce);
            out.println(encIDA);
            out.println(encNB);
            out.println("stop");


        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + ID);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " + ID);
            System.exit(1);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

/*
to use:
start Bob.class
type in two inputs
first input: alice ID
second input: alice Nonce
 */