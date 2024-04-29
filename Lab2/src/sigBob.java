import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

public class sigBob {
    static int nonce = 1 + (int) (Math.random() * 99999);
    static String bobNonce = Integer.toString(nonce);

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    //essentially try to recreate the signature, and compare it with the sent signature
    public static boolean verifySig(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes("UTF8"));
        byte[] sigToBytes = Base64.getDecoder().decode(signature);
        return sig.verify(sigToBytes);
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
        ObjectOutputStream publicStream = new ObjectOutputStream(new FileOutputStream("sigBobPublicKey.xx"));
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
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("sigAlicePublicKey.xx"));
            PublicKey aliceKey = (PublicKey) inputStream.readObject();
            System.out.println("THIS IS ALICE'S PUBLIC KEY: " + aliceKey.toString());
            inputStream.close();

            String inputLine;

            //Initiate conversation with client
            String[] rec = new String[3]; //rec[0] is alice id, rec[1] is N_a
            int index = 0;


            while (!Objects.equals(inputLine = in.readLine(), "stop")) {
                rec[index] = inputLine;
                index++;
            }
            System.out.println("\nReceived Message: " + String.join(" || ", rec));
            boolean check = verifySig("AliceSignature", rec[1], aliceKey);

            System.out.println("\nvalid: " + check);

            out.println(rec[2]);
            out.println("stop");


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
