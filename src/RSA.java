import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RSA {

    public static PublicKey RSA_PUBLIC_KEY;
    public static PrivateKey RSA_PRIVATE_KEY;
    public static String PUBLIC_KEY = System.getProperty("user.home") + "\\Desktop\\public.key";
    public static String PRIVATE_KEY = System.getProperty("user.home") + "\\Desktop\\private.key";

    public static void generateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        final KeyPair key = keyGen.generateKeyPair();
        RSA_PRIVATE_KEY = key.getPrivate();
        RSA_PUBLIC_KEY = key.getPublic();

        KeyFactory fact = KeyFactory.getInstance("RSA");

        RSAPublicKeySpec pub = fact.getKeySpec(key.getPublic(),
                RSAPublicKeySpec.class);
        saveToFile(PUBLIC_KEY,
                pub.getModulus(), pub.getPublicExponent());

        RSAPrivateKeySpec priv = fact.getKeySpec(key.getPrivate(),
                RSAPrivateKeySpec.class);
        saveToFile(PRIVATE_KEY,
                priv.getModulus(), priv.getPrivateExponent());
    }

    public static String encryptRSA(String text) {
        long time = System.nanoTime();
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //cipher.init(Cipher.ENCRYPT_MODE, readPublicKey(PUBLIC_KEY));
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
            //cipher.init(Cipher.DECRYPT_MODE, readPrivateKey(PRIVATE_KEY));
            cipher.init(Cipher.DECRYPT_MODE, RSA_PRIVATE_KEY);
            dectyptedText = cipher.doFinal(DatatypeConverter.parseBase64Binary(text));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        long time2 = System.nanoTime();
        System.out.println("RSA decrypt " + (time2 - time));
        return new String(dectyptedText);
    }

    private static void saveToFile(String fileName,
                                   BigInteger mod,
                                   BigInteger exp)
            throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            oout.close();
        }
    }

    private static PublicKey readPublicKey(String filename) throws IOException {
        InputStream in = new FileInputStream(filename);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        PublicKey pubKey = null;
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            pubKey = fact.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            oin.close();
        }
        return pubKey;
    }

    private static PrivateKey readPrivateKey(String filename) throws IOException {
        InputStream in = new FileInputStream(filename);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        PrivateKey privKey = null;
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            privKey = fact.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            oin.close();
        }
        return privKey;
    }

}
