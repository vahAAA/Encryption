import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class Encryption {

    //HARDCODED, should be changed

    public static String MESSAGE_FILENAME = System.getProperty("user.home") + "\\Desktop\\message.txt";
    public static String ENCRYPT_FILENAME_AES = System.getProperty("user.home") + "\\Desktop\\encryptedAES.txt";
    public static String ENCRYPT_FILENAME_RSA = System.getProperty("user.home") + "\\Desktop\\encryptedRSA.txt";
    public static String DECRYPT_FILENAME_AES = System.getProperty("user.home") + "\\Desktop\\decryptedAES.txt";
    public static String DECRYPT_FILENAME_RSA = System.getProperty("user.home") + "\\Desktop\\decryptedRSA.txt";
    public static String key = "Bar12345Bar12345";
    public static String initVector = "RandomInitVector";

    /**
     * param ifEncrypt decides whether we will encrypt or decrypt data
     *
     * for now you should change methods, in case you want to use AES instead of RSA (to be changed)
     */
    private static void readFromFile(String key, String initVector, boolean ifEncrypt, String filename, boolean ifRSA) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new FileInputStream(filename), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            if (ifEncrypt) {
                writeToFile(AES.encryptAES(key, initVector, line), ENCRYPT_FILENAME_AES);
                writeToFile(RSA.encryptRSA(line), ENCRYPT_FILENAME_RSA);
            } else {
                if(ifRSA)
                    writeToFile(RSA.decryptRSA(line), DECRYPT_FILENAME_RSA);
                else
                    writeToFile(AES.decryptAES(key, initVector, line), DECRYPT_FILENAME_AES);

            }
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

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        //generating RSA keys
        RSA.generateKey();

        //Read message from file and encrypt with AES
        readFromFile(key, initVector, true, MESSAGE_FILENAME,true);

        //Read encrypted message from file and decrypt with AES
        readFromFile(key, initVector, false, ENCRYPT_FILENAME_AES,false);

        //Read encrypted message from file and decrypt with AES
        readFromFile(key, initVector, false, ENCRYPT_FILENAME_RSA,true);
    }
}

