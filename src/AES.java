import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AES {

    public static String encryptAES(String key, String initVector, String value) {
        long time = System.nanoTime();
        byte[] encrypted = null;
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            encrypted = cipher.doFinal(value.getBytes());
            System.out.println("Message was encrypted");


        } catch (Exception ex) {
            ex.printStackTrace();
        }
        long time2 = System.nanoTime();
        System.out.println("AES encrypt " + (time2 - time));
        return DatatypeConverter.printBase64Binary(encrypted);
    }

    public static String decryptAES(String key, String initVector, String encrypted) {
        long time = System.nanoTime();
        byte[] original = null;
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            original = cipher.doFinal(DatatypeConverter.parseBase64Binary(encrypted));
            System.out.println("Message was decrypted");
            long time2 = System.nanoTime();
            System.out.println("AES decrypt " + (time2 - time));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new String(original);
    }
}
