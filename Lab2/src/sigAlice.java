import javax.swing.plaf.synth.SynthIcon;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

public class sigAlice {
    static int nonce = 1 + (int) (Math.random() * 99999);
    static String aliceNonce = Integer.toString(nonce);

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static String signature(String toSign, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(toSign.getBytes("UTF8"));
        byte[] sig = signature.sign();
        return Base64.getEncoder().encodeToString(sig);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("nonce: " + nonce);
        String ID = "alice";
        int portNum = 4999;
        String userInput, encrypted, incoming;
        String[] received = new String[3];
        int index = 0;

        //creating keypair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //storing public and private keys in files
        System.out.println("creating publicKey file");
        ObjectOutputStream publicStream = new ObjectOutputStream(new FileOutputStream("sigAlicePublicKey.xx"));
        publicStream.writeObject(publicKey);
        publicStream.close();

        //creating rsa class for encryption/decryption
        RSA rsa = new RSA();


        try (
                Socket aliceSocket = new Socket("localhost", portNum);
                PrintWriter out = new PrintWriter(aliceSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(aliceSocket.getInputStream()));
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
        ) {
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("sigBobPublicKey.xx"));
            PublicKey bobKey = (PublicKey) inputStream.readObject();
            //System.out.println("THIS IS BOB'S PUBLIC KEY: " + bobKey.toString());
            inputStream.close();

            out.println("COE817Project3");
            out.println(signature("AliceSignature", privateKey));
            out.println(aliceNonce);
            out.println("stop");

            while (!Objects.equals(incoming = in.readLine(), "stop")) {
                System.out.println(incoming);
                received[index] = incoming;
                index++;
            }

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
//
//            //double decoding alice Nonce, using alice private key, then bob public key
//            //String RSAmyNonce_PUB = rsa.privateDecrypt(received[0], privateKey);
//            String RSAmyNonce_PUB_PRA = rsa.publicDecrypt(received[0], bobKey);
//            String bobNonce = received[1];
//            System.out.println("Received Message 2 decoded: " + RSAmyNonce_PUB_PRA + " || " + bobNonce);
//
//            //double encoding bob's nonce using alice private key, then bob public key
//            String bobNonce_PRA = rsa.privateEncrypt(bobNonce, privateKey);
//            //String bobNonce_PRA_PUB = rsa.publicEncrypt(bobNonce_PRA, bobKey);
//            out.println(bobNonce_PRA);
//            out.println("stop");


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
