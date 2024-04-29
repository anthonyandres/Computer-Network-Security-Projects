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

public class publicAlice {

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

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws Exception {
        String ID = "alice";
        int portNum = 4999;
        String userInput, encrypted, incoming;
        String[] received = new String[3];
        //String checkEncode = "encrypted~";
        int index = 0;
        //SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        //DES des = new DES(key);

        //creating keypair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        //System.out.println("Public key:" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        //System.out.println("Private key:" + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        //storing public and private keys in files
        System.out.println("creating publicKey file");
        ObjectOutputStream publicStream = new ObjectOutputStream(new FileOutputStream("AlicePublicKey.xx"));
        publicStream.writeObject(publicKey);
        publicStream.close();
//        ObjectOutputStream privateStream = new ObjectOutputStream(new FileOutputStream("AlicePrivateKey.xx"));//no need to store in file
//        privateStream.writeObject(privateKey);
//        privateStream.close();

        //creating rsa class for encryption/decryption
        RSA rsa = new RSA();


        try (
                Socket aliceSocket = new Socket("localhost", portNum);
                PrintWriter out = new PrintWriter(aliceSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(aliceSocket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
        ) {
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("BobPublicKey.xx"));
            PublicKey bobKey = (PublicKey) inputStream.readObject();
            System.out.println("THIS IS BOB'S PUBLIC KEY: " + bobKey.toString());
            inputStream.close();

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

            //double decoding alice Nonce, using alice private key, then bob public key
            //String RSAmyNonce_PUB = rsa.privateDecrypt(received[0], privateKey);
            String RSAmyNonce_PUB_PRA = rsa.publicDecrypt(received[0], bobKey);
            String bobNonce = received[1];
            System.out.println("Received Message 2 decoded: " + RSAmyNonce_PUB_PRA + " || " + bobNonce);

            //double encoding bob's nonce using alice private key, then bob public key
            String bobNonce_PRA = rsa.privateEncrypt(bobNonce, privateKey);
            //String bobNonce_PRA_PUB = rsa.publicEncrypt(bobNonce_PRA, bobKey);
            out.println(bobNonce_PRA);
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
NOTE:
I encountered issues when trying to double encode
just by the nature of RSA encryption, i could not find a way to double encrypt anything without running into byte block limitation issues
because of this, i did not do the outer encoding in the diagrams
message 2 is only encoded using bob's private key, and decoded using bob's public key
message 3 is only encoded using alice's private key, and decoded using alice's public key
 */
