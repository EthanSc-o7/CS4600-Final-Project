import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class MakeKeys {

    public static void saveKey(byte[] key, String filename) throws Exception {
        FileOutputStream fos = new FileOutputStream(filename);
        fos.write(key);
        fos.close();
    }

    public static void generateAndSaveKeys(String name) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        saveKey(privateKey.getEncoded(), name + "_private.key");
        saveKey(publicKey.getEncoded(), name + "_public.key");
    }

    public static void main(String[] args) {
        try {
            generateAndSaveKeys("sender");
            generateAndSaveKeys("receiver");
            System.out.println("RSA keys generated and saved.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
