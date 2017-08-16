import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;


public class Encryption {

    //HARDCODED, should be changed
    public static String ENCRYPT_FILENAME = "C:\\Users\\mmif__000\\Desktop\\encrypted.txt";
    public static String MESSAGE_FILENAME = "C:\\Users\\mmif__000\\Desktop\\message.txt";
    public static String DECRYPT_FILENAME = "C:\\Users\\mmif__000\\Desktop\\decrypted.txt";
    public static String key = "Bar12345Bar12345";
    public static String initVector = "RandomInitVector";

    /**
     * param ifEncrypt decides whether we will encrypt or decrypt data
     *
     * for now you should change methods, in case you want to use AES instead of RSA (to be changed)
     */
    private static void readFromFile(String key, String initVector, boolean ifEncrypt, String filename) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new FileInputStream(filename), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            if (ifEncrypt) {
                //writeToFile(AES.encryptAES(key, initVector, line), ENCRYPT_FILENAME);
                writeToFile(RSA.encryptRSA(line), ENCRYPT_FILENAME);
            } else {
                //writeToFile(AES.decryptAES(key, initVector, line), DECRYPT_FILENAME);
                writeToFile(RSA.decryptRSA(line), DECRYPT_FILENAME);
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

    public static void main(String[] args) throws NoSuchAlgorithmException {

        //generating RSA keys
        RSA.generateKey();

        //Read message from file and encrypt with AES
        readFromFile(key, initVector, true, MESSAGE_FILENAME);

        //Read encrypted message from file and decrypt with AES
        readFromFile(key, initVector, false, ENCRYPT_FILENAME);
    }
}

