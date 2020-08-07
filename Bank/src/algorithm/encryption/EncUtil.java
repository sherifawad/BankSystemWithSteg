package algorithm.encryption;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class EncUtil {
    public static byte[] readBytes(File inputFile) {
        byte[] outputBytes = new byte[0];
        byte[] inputBytes = new byte[0];
        try {

            FileInputStream inputStream = new FileInputStream(inputFile);
            inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            inputStream.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return inputBytes;
    }


    public static byte[] concatenateCipherByteArrays(byte[] salt, byte[] iv , byte[] cipher) {
        byte[] result = new byte[salt.length + iv.length + cipher.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(iv, 0, result, salt.length, iv.length);
        System.arraycopy(cipher, 0, result, iv.length, cipher.length);
        return result;
    }


    public static byte[] arrayByteConcatenate(byte[] salt, byte[] iv, byte[] Cipher){
        byte[] array = null;
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            outputStream.write(salt);
            outputStream.write(iv);
            outputStream.write(Cipher);
            outputStream.flush();
            outputStream.close();
            array = outputStream.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return array;
    }

    static byte[] arrayByteSplit(byte[] originalArray, Integer from, Integer to){
        byte[] outArray = Arrays.copyOfRange(originalArray, from, to);
        return outArray;
    }

    static byte[] salt (char[] password, byte[] salt) {
        SecretKeyFactory skf = null;
        byte[] res = new byte[0];
        try {
            skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec spec = new PBEKeySpec(password, salt, 100000, 128);
            SecretKey key = skf.generateSecret(spec);
            res = key.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return res;
    }
}
