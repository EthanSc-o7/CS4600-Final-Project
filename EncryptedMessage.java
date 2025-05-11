public class EncryptedMessage {
    byte[] encryptMessage;
    byte[] encryptIV;

    EncryptedMessage(byte[] encryptMessage, byte[] encryptIV){
        this.encryptMessage = encryptMessage;
        this.encryptIV = encryptIV;
    }

}
