package algorithm.encryption;

//import org.jetbrains.annotations.Nullable;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;

import static algorithm.encryption.EncUtil.*;

public class AESencryption {
    public static byte[] ctrMode(int cipherMode, byte[] key, Integer keyLength, byte[] inputBytes) {
        byte[] outputBytes = new byte[0];
        IvParameterSpec spec;
        byte[] nonce;
        try {
            SecretKey secretKey = new SecretKeySpec(key, 0, keyLength, "AES");

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
//            cipher.init(cipherMode, secretKey, spec);

            switch (cipherMode) {
                case Cipher.ENCRYPT_MODE:
                    nonce = new byte[keyLength];
                    SecureRandom random = new SecureRandom();
//            SecureRandom random = SecureRandom.getInstanceStrong();
                    random.nextBytes(nonce);
                    spec = new IvParameterSpec(nonce);
                    cipher.init(cipherMode, secretKey, spec);

//                    outputBytes = arrayByteConcatenate(nonce, cipher.doFinal(inputBytes));
                    break;
                case Cipher.DECRYPT_MODE:
                    nonce = arrayByteSplit(inputBytes, 0, keyLength);
                    spec = new IvParameterSpec(nonce);
                    cipher.init(cipherMode, secretKey, spec);
                    outputBytes = cipher.doFinal(arrayByteSplit(inputBytes, keyLength, inputBytes.length));
                    break;

                default:
                    System.out.println("UnKnown");
                    break;
            }


        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | InvalidParameterException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return outputBytes;
    }

    public static byte[] gcmMode(int gcmCipherMode,  byte[] aadHeader, char[] password, byte[] inputBytes) {
        byte[] outputBytes = null;
        byte[] salt;
        byte[] iv;
        byte[] cipher;
        byte[] res;
        SecretKeySpec ks;
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            switch (gcmCipherMode) {
                case Cipher.ENCRYPT_MODE:
                    salt = new byte[16]; random.nextBytes(salt);
                    iv = new byte[12]; random.nextBytes(iv);
                    res = salt(password, salt);
                    ks = new SecretKeySpec(res, "AES");
                    c.init(Cipher.ENCRYPT_MODE, ks, new GCMParameterSpec(128, iv));
                    if (aadHeader != null) {
                        c.updateAAD(aadHeader);
                    }
                    cipher = c.doFinal(inputBytes);
//                    outputBytes = concatenateCipherByteArrays(salt, iv, cipher);
                    outputBytes = arrayByteConcatenate(salt, iv, cipher);
//                    outputBytes = arrayByteConcatenate(salt, iv);
//                    outputBytes = arrayByteConcatenate(outputBytes, cipher);
                    break;
                case Cipher.DECRYPT_MODE:
                    if (inputBytes.length < 48) {
                        return null;
                    }
                    salt = Arrays.copyOfRange(inputBytes, 0, 16);
//                    salt = arrayByteSplit(inputBytes, 0, 16);
                    iv = Arrays.copyOfRange(inputBytes, 16, 28);
//                    iv = arrayByteSplit(inputBytes, 16, 28);
//                        byte[] es = Arrays.copyOfRange(os, 28, os.length);
//                    cipher = arrayByteSplit(inputBytes, 16, 28);
                    cipher = Arrays.copyOfRange(inputBytes, 28, inputBytes.length);
                    res = salt(password, salt);
                    ks = new SecretKeySpec(res, "AES");
                    c.init(Cipher.DECRYPT_MODE, ks, new GCMParameterSpec(128, iv));
                    if (aadHeader != null) {
                        c.updateAAD(aadHeader);
                    }                        // Return our Decrypted String
                    outputBytes = c.doFinal(cipher);

                    break;

                default:
                    System.out.println("UnKnown");
                    break;
            }


        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | InvalidParameterException
                | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return outputBytes;
    }

    public static byte[] encrypt(byte[] key, byte[] plainText) {
        byte[] result = new byte[plainText.length];
        for (int i = 0; i < plainText.length; i++) {
            result[i] = (byte) (plainText[i] ^ key[i]);
        }

        return result;
    }

    public static byte[] crypt(byte[] bytes, byte[] key) {
        int size = bytes != null ? bytes.length : 0;
        final byte[] encoded = new byte[size];
        int keySize = key != null ? key.length : 0;
        // loop on input bytes
        for (int i = 0; i < size; i++) {
            // shift key index (assuming key <= bytes)
            int keyi = i >= keySize ? size % (keySize-1) : i;
            // pad
            encoded[i] = (byte) (bytes[i] ^ key[keyi]);
        }
        return encoded;
    }

}


