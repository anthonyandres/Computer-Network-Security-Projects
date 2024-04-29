import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

public class RSA {

    Cipher encryptCipher, decryptCipher;

    RSA() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        encryptCipher = Cipher.getInstance("RSA");
        decryptCipher = Cipher.getInstance("RSA");
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(128);
        return keyPairGenerator.generateKeyPair();
    }

    public String publicEncrypt(String toEncrypt, PublicKey publicKey) throws Exception{
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] utf8 = toEncrypt.getBytes("UTF8");
        byte[] encrypted = encryptCipher.doFinal(utf8);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String privateEncrypt(String toEncrypt, PrivateKey privateKey) throws Exception{
        encryptCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] utf8 = toEncrypt.getBytes("UTF8");
        byte[] encrypted = encryptCipher.doFinal(utf8);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String publicDecrypt(String toDecrypt, PublicKey publicKey) throws Exception{
        decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decrypt = Base64.getDecoder().decode(toDecrypt);
        byte[] output = decryptCipher.doFinal(decrypt);
        return new String(output, "UTF8");
    }

    public String privateDecrypt(String toDecrypt, PrivateKey privateKey) throws Exception{
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypt = Base64.getDecoder().decode(toDecrypt);
        byte[] output = decryptCipher.doFinal(decrypt);
        return new String(output, "UTF8");
    }


    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        RSA rsa = new RSA();

        String msg = "hello world!";
        String encrypt = rsa.publicEncrypt(msg, publicKey);
        System.out.println(encrypt);

        String decrypt = rsa.privateDecrypt(encrypt, privateKey);
        System.out.println(decrypt);

        System.out.println("Public key:" + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("Private key:" + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
    }


}
