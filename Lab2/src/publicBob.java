import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

public class publicBob {
    static int nonce = 1 + (int) (Math.random() * 99999);
    static String bobNonce = Integer.toString(nonce);

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        System.out.println("nonce: " + nonce);
        String ID = "bob";
        int portNumber = 4999;

        //creating keypair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        //System.out.println("Public key:" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        //System.out.println("Private key:" + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        //storing public key in file
        System.out.println("creating publicKey file");
        ObjectOutputStream publicStream = new ObjectOutputStream(new FileOutputStream("BobPublicKey.xx"));
        publicStream.writeObject(publicKey);
        publicStream.close();

        //creating rsa class for encryption/decryption
        RSA rsa = new RSA();


        try (
                ServerSocket serverSocket = new ServerSocket(portNumber);
                Socket clientSocket = serverSocket.accept();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        ) {
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("AlicePublicKey.xx"));
            PublicKey aliceKey = (PublicKey) inputStream.readObject();
            System.out.println("THIS IS ALICE'S PUBLIC KEY: " + aliceKey.toString());
            inputStream.close();

            String inputLine, outputLine, decodedMessage;

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

            //double encoding alice's nonce using bob private key, then bob public key
            String encryptedNA_PRB = rsa.privateEncrypt(rec[1], privateKey);
            System.out.println("\n\nEncrypted once with bobs private key: "+encryptedNA_PRB+"\n" + encryptedNA_PRB.length()+"\n");
            //String encryptedNA_PRB_PUA = rsa.publicEncrypt(encryptedNA_PRB, aliceKey);
            out.println(encryptedNA_PRB);//sending the double encrypted N_a
            out.println(bobNonce);//sending N_b
            out.println("stop");

            index = 0;
            while (!Objects.equals(inputLine = in.readLine(), "stop")) {
                received[index] = inputLine;
                index++;
            }

            //double decoding with bob private key, then alice public key
            //String myNonce_PUB = rsa.privateDecrypt(received[0], privateKey);
            String myNonce_PUB_PRA = rsa.publicDecrypt(received[0], aliceKey);
            System.out.println("Received Message 3 encoded: " + received[0]);
            System.out.println("Received Message 3 decoded: " + myNonce_PUB_PRA);

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

/*
NOTE:
I encountered issues when trying to double encode
just by the nature of RSA encryption, i could not find a way to double encrypt anything without running into byte block limitation issues
because of this, i did not do the outer encoding in the diagrams
message 2 is only encoded using bob's private key, and decoded using bob's public key
message 3 is only encoded using alice's private key, and decoded using alice's public key
 */
