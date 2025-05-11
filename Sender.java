import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

public class Sender {

    // Have the .txt file be encrypted using AES before being sent

       //AES Key for the txt file is itself encrypted with nathan's public key

       //What is sent is encrypted AES key and Encrypted txt

    // Append MAC to data transmitted

    public static SecretKey createAES() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        return generator.generateKey();
    }


    public static EncryptedMessage encryptMessage(File fileName, SecretKey aesKey) throws Exception{
        byte[] message = Files.readAllBytes(fileName.toPath());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[16];

        SecureRandom.getInstanceStrong().nextBytes(iv);

        IvParameterSpec params = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, params);

        byte[] encryptedM = cipher.doFinal(message);
        return new EncryptedMessage(encryptedM, iv);
    }

    public static byte[] encryptAES(SecretKey aesKey, PublicKey pubKey) throws Exception{

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    public static byte[] appendMAC(byte[] encryptedMessage, byte[] encryptedAES, String MACKey) throws Exception{

        SecretKey macKey = new SecretKeySpec(MACKey.getBytes(), "HmacSHA256");

        Mac senderMAC = Mac.getInstance("HmacSHA256");

        senderMAC.init(macKey);

        senderMAC.update(encryptedMessage);
        senderMAC.update(encryptedAES);
        return senderMAC.doFinal();
    }

    public static void transmitData(byte[] data) throws Exception{
        DataOutputStream writeOut = new DataOutputStream(new FileOutputStream("Sent_data.txt"));

        writeOut.writeInt(data.length);
        writeOut.write(data);
    }





    public static void main(String[] args) throws Exception {
        PublicKey receiverPubKey;
        SecretKey senderSecretKey;
        EncryptedMessage encryptedMessage;

        File pubKey = new File("receiver_public.key");
        File message = new File("message.txt");
        byte[] keyBytes = Files.readAllBytes(pubKey.toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);


        receiverPubKey = KeyFactory.getInstance("RSA").generatePublic(spec);

        senderSecretKey = createAES();

        encryptedMessage = encryptMessage(message, senderSecretKey);

        byte[] encryptedAES = encryptAES(senderSecretKey, receiverPubKey);

        byte[] mac = appendMAC(encryptedMessage.encryptMessage, encryptedAES, "mackey");

        transmitData(encryptedMessage.encryptAES);

        transmitData(encryptedAES);

        transmitData(encryptedMessage.encryptMessage);

        transmitData(mac);

    }






}
