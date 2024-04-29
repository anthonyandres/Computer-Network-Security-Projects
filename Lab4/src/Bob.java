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
import java.util.Scanner;

public class Bob {
    static int nonce = 1 + (int) (Math.random() * 99999);
    static String bobNonce = Integer.toString(nonce);

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    public static String chatting(BufferedReader stdIn){
        boolean incomingChat = false;
        Scanner scanner = new Scanner(System.in);
        String message = "";
        //while there is no incoming chats from the other users
        while("".equals(message)){
            System.out.println("type a message: ");
            //while the user is not inputting a message to be sent
            try {
                while (!stdIn.ready()) {
                    Thread.sleep(200);
                }
                message = stdIn.readLine();
            } catch (InterruptedException | IOException e){
                System.out.println("Chat received from other user before this user sent a chat!");
                return null;
            }
        }
        return message;
    }

    public static String signature(String toSign, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(toSign.getBytes("UTF8"));
        byte[] sig = signature.sign();
        return Base64.getEncoder().encodeToString(sig);
    }

    public static String verifySig(String message, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes("UTF8"));
        byte[] sigToBytes = Base64.getDecoder().decode(signature);
        String s = Base64.getEncoder().encodeToString(sigToBytes);
        return s;
    }

    public static String[] socialMedia(BufferedReader stdIn, BufferedReader in) throws InterruptedException, IOException {
        String yaya;
        String check;
        System.out.println("Type your message:\n");
        Scanner scanner = new Scanner(System.in);
        while(true){
            //Thread.sleep(3000);
            if(in.ready()){
                yaya = in.readLine();
                check = "otherUser";
                break;
            }
            //System.out.println("no external message");
            if(stdIn.ready()){
                yaya = scanner.nextLine();
                check = "thisUser";
                break;
            }
            //System.out.println("no user input");

        }
        String[] returnArray = {yaya, check};
        return returnArray;
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
                BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))
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
            String desDecryptedKs = des.decrypt(doubleE1[0]);
            String desDecryptedIDb = des.decrypt(doubleE1[1]);
            System.out.println("encrypted Kab: " + doubleE1[0]);
            System.out.println("encrypted IDa: " + doubleE1[1]);
            System.out.println("decrypted Ks: " + desDecryptedKs);
            System.out.println("decrypted IDa: " + desDecryptedIDb + "\n");

            byte[] decodedKs = Base64.getDecoder().decode(desDecryptedKs);
            SecretKey Ks = new SecretKeySpec(decodedKs, 0, decodedKs.length, "DES");

            System.out.println("\n\n----------------- CHATTING -----------------\n\n");

            String[] chat;
            DES desChat = new DES(Ks);
            String loopNonce;
            while(true){
                loopNonce = in.readLine();
                System.out.println("nonce: " + loopNonce);
                chat = socialMedia(stdIn, in);
                if(chat[1].equals("otherUser")){
                    System.out.print("from other user: " + chat[0] + "\n");
                }
                else{
                    System.out.print("^^^ message sent\n");
                    //out.println(chat[0]);
                    //encoding message and ID with Ks, and generating signature
                    String toSign = ID + " || " + chat[0];
                    String encodedChat = desChat.encrypt(chat[0]);
                    String encodedID = desChat.encrypt(ID);
                    String signature = signature(toSign, privateKey);
                    String loopNonceEncrypt = desChat.encrypt(loopNonce);

                    out.println((encodedID));
                    out.println((encodedChat));
                    out.println((signature));
                    out.println(loopNonceEncrypt);
                    out.println("stop");

                }
            }






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
