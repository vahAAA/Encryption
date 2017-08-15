import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;


public class Encryption {

    //HARDCODED, should be changed
    public static String ENCRYPT_FILENAME = "C:\\Users\\mmif__000\\Desktop\\encrypted.txt";
    public static String MESSAGE_FILENAME = "C:\\Users\\mmif__000\\Desktop\\message.txt";
    public static String DECRYPT_FILENAME = "C:\\Users\\mmif__000\\Desktop\\decrypted.txt";
    public static String key = "Bar12345Bar12345";
    public static String initVector = "RandomInitVector";

    public static PublicKey RSA_PUBLIC_KEY;
    public static PrivateKey RSA_PRIVATE_KEY;

    private static String encryptAES(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            System.out.println("Message was encrypted");
            return DatatypeConverter.printBase64Binary(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static String decryptAES(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(encrypted));
            System.out.println("Message was decrypted");
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * param ifEncrypt decides whether we will encrypt or decrypt data
     */
    private static void readFromFile(String key, String initVector, boolean ifEncrypt, String filename) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new FileInputStream(filename), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            //  while ((line = reader.readLine()) != null) {
            if (ifEncrypt)
                writeToFile(encryptAES(key, initVector, line), ENCRYPT_FILENAME);
            else
                writeToFile(decryptAES(key, initVector, line), DECRYPT_FILENAME);
            //  }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static void writeToFile(String value, String filename) {
        try {
            FileWriter writer = new FileWriter(filename, false);
            writer.write(value);
            writer.flush();
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }


    public static void generateKey() throws NoSuchAlgorithmException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        final KeyPair key = keyGen.generateKeyPair();
        RSA_PRIVATE_KEY = key.getPrivate();
        RSA_PUBLIC_KEY = key.getPublic();
    }


    public static byte [] encryptRSA(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    public static String decryptRSA(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText);
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        //Read message from file and encrypt with AES
        readFromFile(key, initVector, true, MESSAGE_FILENAME);

        //Read encrypted message from file and decrypt with AES
        readFromFile(key, initVector, false, ENCRYPT_FILENAME);

        //generating RSA keys
        generateKey();
        String message = "secret message";
        System.out.println(decryptRSA(encryptRSA(message,RSA_PUBLIC_KEY),RSA_PRIVATE_KEY));
    }
}
