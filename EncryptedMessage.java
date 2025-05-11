public class EncryptedMessage {
    byte[] encryptMessage;
    byte[] encryptAES;

    EncryptedMessage(byte[] encryptMessage, byte[] encryptAES){
        this.encryptMessage = encryptMessage;
        this.encryptAES = encryptAES;
    }

}
