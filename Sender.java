import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Sender {

    // Have the .txt file be encrypted using AES before being sent

       //AES Key for the txt file is itself encrypted with nathan's public key

       //What is sent is encrypted AES key and Encrypted txt

    // Append MAC to data transmitted

    public static PublicKey getPubKey(File fileName) throws IOException {
        byte[] keyBytes = Files.readAllBytes(fileName.toPath());

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey createAES() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(192);
        return generator.generateKey();
    }


    public static EncryptedMessage encryptMessage(File fileName, SecretKey aesKey) throws Exception{
        byte[] message = Files.readAllBytes(fileName.toPath());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKC5Padding");

        byte[] iv = new byte[16];

        SecureRandom.getInstanceStrong().nextBytes(iv);

        IvParameterSpec params = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, params);

        byte[] encryptedM = cipher.doFinal(message);
        return new EncryptedMessage(encryptedM, iv);
    }

    public static byte[] appendMAC(byte[] encryptedMessage, byte[] encryptedAES, String MACKey) throws Exception{

        SecretKey macKey = new SecretKeySpec(MACKey.getBytes(), "HmacSHA256");

        Mac senderMAC = Mac.getInstance("HmacSHA256");

        senderMAC.init(macKey);

        senderMAC.update(encryptedMessage);
        senderMAC.update(encryptedAES);
        return senderMAC.doFinal();
    }





    public static void main(String[] args) {

    }






}
