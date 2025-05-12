import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class Receiver {

    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static SecretKey decryptAESKey(byte[] encryptedAES, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = cipher.doFinal(encryptedAES);
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    public static boolean verifyMAC(byte[] message, byte[] encryptedAES, byte[] receivedMAC, String macKey) throws Exception {
        SecretKey macKeyObj = new SecretKeySpec(macKey.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKeyObj);
        mac.update(message);
        mac.update(encryptedAES);
        byte[] calculatedMAC = mac.doFinal();
        return Arrays.equals(calculatedMAC, receivedMAC);
    }

    public static String decryptMessage(byte[] encryptedMessage, SecretKey aesKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encryptedMessage);
        return new String(decrypted);
    }

    public static void main(String[] args) {
        try {
            // Load receiver's private RSA key
            PrivateKey receiverPrivKey = loadPrivateKey("receiver_private.key");

            // Read from Transmitted_Data.txt
            DataInputStream in = new DataInputStream(new FileInputStream("Transmitted_Data.txt"));

            // Read encrypted AES key
            int aesKeyLen = in.readInt();
            byte[] encryptedAES = new byte[aesKeyLen];
            in.readFully(encryptedAES);

            // Read encrypted message
            int msgLen = in.readInt();
            byte[] encryptedMessage = new byte[msgLen];
            in.readFully(encryptedMessage);

            // Read IV
            int ivLen = in.readInt();
            byte[] iv = new byte[ivLen];
            in.readFully(iv);

            // Read MAC
            int macLen = in.readInt();
            byte[] mac = new byte[macLen];
            in.readFully(mac);

            in.close();

            // Decrypt AES key
            SecretKey aesKey = decryptAESKey(encryptedAES, receiverPrivKey);

            // Verify MAC
            boolean isValid = verifyMAC(encryptedMessage, encryptedAES, mac, "mackey");

            if (!isValid) {
                System.out.println("MAC verification failed! Message integrity compromised.");
                return;
            }

            // Decrypt message
            String original = decryptMessage(encryptedMessage, aesKey, iv);
            System.out.println("Decrypted Message:\n" + original);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
