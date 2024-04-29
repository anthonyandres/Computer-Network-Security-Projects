import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

public class Bob {
    static int nonce = 1 + (int) (Math.random() * 99999);
    static String bobNonce = Integer.toString(nonce);

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        String ID = "bob";
        int myPort = 5000;
        int portNumber = 4999;
        int KDCPort = 4888;
        int otherUserPort = 4777;

        String incoming;
        String[] received = new String[3];
        String[] doubleE = new String[3];
        int index = 0;

        //creating keypair
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        //storing public key in file
        System.out.println("creating publicKey file");
        ObjectOutputStream publicStream = new ObjectOutputStream(new FileOutputStream("BobPublicKey.xx"));
        publicStream.writeObject(publicKey);
        publicStream.close();


        try (
                Socket KDCSocket = new Socket("localhost", KDCPort);
                PrintWriter out = new PrintWriter(KDCSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(KDCSocket.getInputStream()));
        ) {
            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("KDCPublicKey.xx"));
            PublicKey kdcKey = (PublicKey) inputStream.readObject();
            System.out.println("THIS IS KDC'S PUBLIC KEY: " + kdcKey.toString());
            inputStream.close();

            //creating rsa class for encryption/decryption
            RSA rsa = new RSA();

            //sending ID
            System.out.println("Sending ID: " + ID + "\n");
            out.println(ID);

            //receiving NK1 and IDK
            index=0;
            while(!Objects.equals(incoming = in.readLine(), "stop")){
                received[index] = incoming;
                index++;
            }
            String KDCNonce = rsa.privateDecrypt(received[0], privateKey);
            String KDCID = rsa.privateDecrypt(received[1], privateKey);
            System.out.println("incoming encoded message from KDC: [" + received[0] + " || " + received[1] + "]\n");
            System.out.println("incoming message from KDC decoded [KDC nonce || KDC id]: [" + KDCNonce + " || " + KDCID + "]\n");

            //encoding Nonce and nonce from KDC
            String encodedNonce = rsa.publicEncrypt(bobNonce,kdcKey);
            String encodedKDCNonce = rsa.publicEncrypt(KDCNonce, kdcKey);

            //sending encoded nonces
            System.out.println("Sending bob nonce and KDC nonce: [" + bobNonce + " || " + KDCNonce + "]\n" );
            out.println(encodedNonce);
            out.println(encodedKDCNonce);
            out.println("stop");

            //receiving nonce of kdc AGAIN
            incoming = in.readLine();
            String decryptedKDCNonce = rsa.privateDecrypt(incoming, privateKey);
            System.out.println("encrypted N_k: " + incoming);
            System.out.println("decrypted N_k: " + decryptedKDCNonce + "\n");

            //receiving session key
            index = 0;
            while(!Objects.equals(incoming = in.readLine(), "stop")){
                doubleE[index] = incoming;
                index++;
            }

            //decrypting session key
            String decryptedFirstHalf = rsa.privateDecrypt(doubleE[0], privateKey);
            String decryptedSecondHalf = rsa.privateDecrypt(doubleE[1], privateKey);
            String combined = decryptedFirstHalf.concat(decryptedSecondHalf);
            String finalDecryptedSessionKey = rsa.publicDecrypt(combined, kdcKey);
            System.out.println("\nsession key for KDC: " + finalDecryptedSessionKey + "\n");
            byte[] decodedKey = Base64.getDecoder().decode(finalDecryptedSessionKey);
            SecretKey KDCsession = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");


            //PHASE 2
            System.out.println("\n\n----------------- PHASE 2 -----------------\n\n");

            //receiving encrypted shared session key and bob ID
            index = 0;
            String[] doubleE1 = new String[3];
            while(!Objects.equals(incoming = in.readLine(), "stop")){
                doubleE1[index] = incoming;
                index++;
            }

            //decrypting shared session key and bob ID
            DES des = new DES(KDCsession);
            String desDecryptedKab = des.decrypt(doubleE1[0]);
            String desDecryptedIDb = des.decrypt(doubleE1[1]);
            System.out.println("encrypted Kab: " + doubleE1[0]);
            System.out.println("encrypted IDa: " + doubleE1[1]);
            System.out.println("decrypted Kab: " + desDecryptedKab);
            System.out.println("decrypted IDa: " + desDecryptedIDb + "\n");








        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + ID);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " + ID);
            System.exit(1);
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
