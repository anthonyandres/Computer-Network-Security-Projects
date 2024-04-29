import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

//import static javax.swing.text.rtf.RTFAttributes.BooleanAttribute.True;

public class KDCThread extends Thread {
    static SecretKey keyAB;

    static {
        try {
            keyAB = KeyGenerator.getInstance("DES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static int threadCount = 0;
    static String ALICEID, BOBID;
    private Socket socket = null;
    PrivateKey KDCPrivateKey;
    int nonce = 1 + (int) (Math.random() * 99999);
    String KDCnonce = Integer.toString(nonce);
    String ID_k = "kdc";
    String incoming, join;
    String[] received = new String[3];
    String[] decrypted = new String[3];
    int index = 0;

    public KDCThread(Socket socket){
        super("MultiServerThread");
        this.socket = socket;
    }


    public void run(){
        try(
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        ){
            //Server Logic goes here
            //PHASE 1
            String ID;
            ObjectInputStream kdcinput = new ObjectInputStream(new FileInputStream("KDCPrivateKey.xx"));
            KDCPrivateKey = (PrivateKey) kdcinput.readObject();
            RSA rsa = new RSA();

            //KDC receives ID from user A or B, ID_a = 'alice' and ID_b = 'bob'
            ID = in.readLine();
            System.out.println("Received ID: " + ID);
            //getting public key for either alice or bob
            if(ID.equals("alice")){
                System.out.println("\n\n-----------------COMMUNICATING WITH ALICE-----------------\n\n");
                ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("AlicePublicKey.xx"));
                PublicKey aliceKey = (PublicKey) inputStream.readObject();
                System.out.println("THIS IS ALICE'S PUBLIC KEY: " + aliceKey.toString() + "\n\n");

                //encrypting [nonce || ID_k]
                String encryptedNonce = rsa.publicEncrypt(KDCnonce,aliceKey);
                String encryptedIDK = rsa.publicEncrypt(ID_k,aliceKey);

                //sending E(PU_a, [N_k || ID_k])
                System.out.println("Sending KDC nonce: " + KDCnonce + "\nSending KDC ID: " + ID_k + "\n");
                System.out.println("encrypted Nonce: " + encryptedNonce + "\n");
                System.out.println("encrypted ID: " + encryptedIDK + "\n");
                out.println(encryptedNonce);
                out.println(encryptedIDK);
                out.println("stop");

                //receiving E(PU_k, [N_a || N_k])
                while(!Objects.equals(incoming = in.readLine(), "stop")){
                    received[index] = incoming;
                    index++;
                }
                join = String.join(" || ", received);
                System.out.println("Received from alice:\n" + join + "\n");

                //decrypting using KDC's Private Key, decrypted[0] = Nonce from alice, decrypted[1] = initial nonce sent by kdc
                decrypted[0] = rsa.privateDecrypt(received[0], KDCPrivateKey);
                decrypted[1] = rsa.privateDecrypt(received[1], KDCPrivateKey);
                System.out.println("Nonce from alice: " + decrypted[0]+ "\n");
                System.out.println(("N_k according to alice: " + decrypted[1] + "\n"));
                if(decrypted[1].equals(KDCnonce)){
                    System.out.println("Alice sent the same N_k\n");
                }
                else{
                    System.out.println("ALICE DID NOT SEND THE SAME N_k!!!!!\n");
                }

                //sending encrypted N_k
                out.println(encryptedNonce);
                //out.println("stop");

                //double encrypting symmetric key K_a
                //encrypting with KDC private key
                SecretKey keyA = KeyGenerator.getInstance("DES").generateKey();
                String aliceSymmetricKey = Base64.getEncoder().encodeToString(keyA.getEncoded());
                String innerEncrypt = rsa.privateEncrypt(aliceSymmetricKey, KDCPrivateKey);
                //splitting encryption in half for further encryption (this is done so that the size of the string to encrypt is not too big)
                int middle = innerEncrypt.length()/2;
                String[] half = {innerEncrypt.substring(0, middle), innerEncrypt.substring(middle)};
                //encrypting the first half
                String firstHalfEncrypt = rsa.publicEncrypt(half[0], aliceKey);
                String secondHalfEncrypt = rsa.publicEncrypt(half[1], aliceKey);

                //sending double encrypted symmetric key K_a
                System.out.println("Sending shared Key: " + aliceSymmetricKey + "\n");
                out.println(firstHalfEncrypt);
                out.println(secondHalfEncrypt);
                out.println("stop");



                //PHASE 2
                //receiving ID of alice and ID of Bob
                System.out.println("\n\n----------------- PHASE 2 -----------------\n\n");
                index = 0;
                String[] received1 = new String[3];
                while(!Objects.equals(incoming = in.readLine(), "stop")){
                    received1[index] = incoming;
                    index++;
                }
                //setting Static variable for KDC to use to send to BOB
                ALICEID = received1[0];
                BOBID = received1[1];
                System.out.println("\nID Alice: " + received1[0] + "\nID Bob: " + received1[1] + "\n");

                //encrypting Kab and IDb
                String Kab = Base64.getEncoder().encodeToString(keyAB.getEncoded());
                DES des = new DES(keyA);
                String desEncryptedKab = des.encrypt(Kab);
                String desEncryptedIDb = des.encrypt(received1[1]);

                //sending the session key between A and B
                System.out.println("Kab: " + Kab + "\nIDb: " + received1[1]);
                System.out.println("Sending encrypted Kab session key: " + desEncryptedKab + "\n" + "Sending encrypted IDb: " + desEncryptedIDb);
                out.println(desEncryptedKab);
                out.println(desEncryptedIDb);
                out.println("stop");




                inputStream.close();
            }
            else if(ID.equals("bob")){
                System.out.println("\n\n-----------------COMMUNICATING WITH BOB-----------------\n\n");
                ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("BobPublicKey.xx"));
                PublicKey bobKey = (PublicKey) inputStream.readObject();
                System.out.println("THIS IS BOB'S PUBLIC KEY: " + bobKey.toString() + "\n\n");

                //encrypting [nonce || ID_k]
                String encryptedNonce = rsa.publicEncrypt(KDCnonce,bobKey);
                String encryptedIDK = rsa.publicEncrypt(ID_k,bobKey);

                //sending E(PU_a, [N_k || ID_k])
                System.out.println("Sending KDC nonce: " + KDCnonce + "\nSending KDC ID: " + ID_k + "\n");
                System.out.println("encrypted Nonce: " + encryptedNonce + "\n");
                System.out.println("encrypted ID: " + encryptedIDK + "\n");
                out.println(encryptedNonce);
                out.println(encryptedIDK);
                out.println("stop");

                //receiving E(PU_k, [N_a || N_k])
                while(!Objects.equals(incoming = in.readLine(), "stop")){
                    received[index] = incoming;
                    index++;
                }
                join = String.join(" || ", received);
                System.out.println("Received from bob:\n" + join + "\n");

                //decrypting using KDC's Private Key, decrypted[0] = Nonce from alice, decrypted[1] = initial nonce sent by kdc
                decrypted[0] = rsa.privateDecrypt(received[0], KDCPrivateKey);
                decrypted[1] = rsa.privateDecrypt(received[1], KDCPrivateKey);
                System.out.println("Nonce from bob: " + decrypted[0]+ "\n");
                System.out.println(("N_k according to bob: " + decrypted[1] + "\n"));
                if(decrypted[1].equals(KDCnonce)){
                    System.out.println("Bob sent the same N_k\n");
                }
                else{
                    System.out.println("BOB DID NOT SEND THE SAME N_k!!!!!\n");
                }

                //sending encrypted N_k
                out.println(encryptedNonce);
                //out.println("stop");

                //double encrypting symmetric key K_a
                //encrypting with KDC private key
                SecretKey keyB = KeyGenerator.getInstance("DES").generateKey();
                String bobSymmetricKey = Base64.getEncoder().encodeToString(keyB.getEncoded());
                String innerEncrypt = rsa.privateEncrypt(bobSymmetricKey, KDCPrivateKey);
                //splitting encryption in half for further encryption (this is done so that the size of the string to encrypt is not too big)
                int middle = innerEncrypt.length()/2;
                String[] half = {innerEncrypt.substring(0, middle), innerEncrypt.substring(middle)};
                //encrypting the first half
                String firstHalfEncrypt = rsa.publicEncrypt(half[0], bobKey);
                String secondHalfEncrypt = rsa.publicEncrypt(half[1], bobKey);

                //sending double encrypted symmetric key K_a
                System.out.println("Sending shared Key: " + bobSymmetricKey + "\n");
                out.println(firstHalfEncrypt);
                out.println(secondHalfEncrypt);
                out.println("stop");



                //PHASE 2
                //receiving ID of alice and ID of Bob
                System.out.println("\n\n----------------- PHASE 2 -----------------\n\n");

                System.out.println("KDC already knows Alice ID using static variable: " + ALICEID);

                //encrypting Kab and IDa
                String Kab = Base64.getEncoder().encodeToString(keyAB.getEncoded());
                DES des = new DES(keyB);
                String desEncryptedKab = des.encrypt(Kab);
                String desEncryptedIDb = des.encrypt(ALICEID);

                //sending the session key between A and B
                System.out.println("Kab: " + Kab + "\nIDb: " + ALICEID);
                System.out.println("Sending encrypted Kab session key: " + desEncryptedKab + "\n" + "Sending encrypted IDb: " + desEncryptedIDb);
                out.println(desEncryptedKab);
                out.println(desEncryptedIDb);
                out.println("stop");




                inputStream.close();
            }

            socket.close();
        } catch(IOException e){
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}