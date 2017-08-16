import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.*;

public class RSA {
    public static PublicKey RSA_PUBLIC_KEY;
    public static PrivateKey RSA_PRIVATE_KEY;

    public static void generateKey() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        final KeyPair key = keyGen.generateKeyPair();
        RSA_PRIVATE_KEY = key.getPrivate();
        RSA_PUBLIC_KEY = key.getPublic();
    }

    public static String encryptRSA(String text) {
        long time = System.nanoTime();
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, RSA_PUBLIC_KEY);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        long time2 = System.nanoTime();
        System.out.println("RSA encrypt " + (time2 - time));
        return DatatypeConverter.printBase64Binary(cipherText);
    }

    public static String decryptRSA(String text) {
        long time = System.nanoTime();
        byte[] dectyptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, RSA_PRIVATE_KEY);
            dectyptedText = cipher.doFinal(DatatypeConverter.parseBase64Binary(text));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        long time2 = System.nanoTime();
        System.out.println("RSA decrypt " + (time2 - time));
        return new String(dectyptedText);
    }

}
