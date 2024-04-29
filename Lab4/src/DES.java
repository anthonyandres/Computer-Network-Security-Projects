import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class DES {

    Cipher encryptCipher, decryptCipher;

    DES(SecretKey key)throws Exception{
        encryptCipher = Cipher.getInstance("DES");
        decryptCipher = Cipher.getInstance("DES");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        decryptCipher.init(Cipher.DECRYPT_MODE, key);
    }

//    public SecretKey generateKey(String password, String random) throws Exception{
//        //SecretKey key = KeyGenerator.getInstance("DES").generateKey();
//        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//        KeySpec spec = new PBEKeySpec(password.toCharArray(), random.getBytes(), 65536, 128);
//        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "DES");
//        return secret;
//    }

    public String encrypt(String toEncrypt) throws Exception{
        byte[] utf8 = toEncrypt.getBytes("UTF8");
        byte[] encrypted = encryptCipher.doFinal(utf8);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String toDecrypt) throws Exception{
        byte[] decrypt = Base64.getDecoder().decode(toDecrypt);
        byte[] output = decryptCipher.doFinal(decrypt);
        return new String(output, "UTF8");
    }

}
