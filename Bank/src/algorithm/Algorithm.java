package algorithm;

import Util.Uty;
import algorithm.Steganograpgy.Embedding;
import algorithm.Steganograpgy.Extracting;
import algorithm.ecc.ECPoint;
import connection.BankServer;
import parameters.Clients;
import parameters.PublicKey;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import static Util.Uty.*;
import static algorithm.encryption.EncUtil.readBytes;

public class Algorithm {
    private final BankServer bankClient;
    private ECPoint p_C2;

    public Algorithm(BankServer bankClient) {
        this.bankClient = bankClient;
    }

    public HashMap<String, Object> signcryption(String[] srcFiles, Path tempDir, String text) throws IOException {


//        text = "1236547896541596";
        BigInteger r_b;
        Clients clientInfo = bankClient.ClientAccountNumber(text);
        if (clientInfo == null) {
            System.out.println("Unknown Client");
            return null;
        }


//        ECPoint x = new ECPoint(new BigInteger("57903356541901510574031068088123503637723069443"), new BigInteger("641777948366584055162521257065766432070889685782"));
//        ECPoint y = new ECPoint(new BigInteger("1034727440928405776341788179895254642737747575696"), new BigInteger("1265783754848435827721873432765201904052689072609"));
//        clientInfo.setPublicKey(new PublicKey(x, y));

        if (bankClient.getPublicParameter() == null) {
            System.out.println("PublicParameter is null");
            return null;
        }
        if (clientInfo.getPublicKey() == null) {
            System.out.println("Client PublicKey is null");
            return null;
        }

//        do {
//                r_c = Uty.randomBig(bankClient.getPublicParameter().getOrder());
//            } while (r_c == null);
//        System.out.println("r_c " + r_c);

        r_b = new BigInteger("458291618404360041825964642263159512352099041083");

        ECPoint z_b = bankClient.getPublicParameter().getCurve().multiply(bankClient.getPublicParameter().getBasePoint(), r_b);
//        ECPoint K_1 = bankClient.getPublicParameter().getCurve().multiply(bankClient.getBankParameter().getPointOfBankPartialKey(), r_c);
        ECPoint K_1 = bankClient.getPublicParameter().getCurve().multiply(pointOfClientPartialKey(clientInfo), r_b);
        byte[] Key = K_1.x.toByteArray();
//        System.out.println("Encryption Key " + Arrays.toString(Key));


        HashMap<String, Object> AccountHshMap = new HashMap<>();
        AccountHshMap.put("IDb",  bankClient.getBankParameter().getBankID());
        AccountHshMap.put("t", currentDate());
        byte[] cipherAccount = Uty.xorWithKey(mapTOByte(AccountHshMap), K_1.y.toByteArray());


        String pathFile = tempDir + "/Source.zip";
        Uty.zip(pathFile, srcFiles);

        byte[] cipherText = new byte[0];
        try {
            cipherText = Uty.xorWithKey(readBytes(new File(pathFile)), Key);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }


//        System.out.println("getBankID " + bankClient.getBankParameter().getBankID());
        System.out.println("K_1.y " + K_1.y);
//        byte[] IDc = Uty.xor( (bankClient.getBankParameter().getBankID().getBytes()), K_1.y.toByteArray());

//        byte[] IDc = Uty.xor(bankClient.getBankParameter().getBankID().getBytes("UTF-8"), K_1.y.toByteArray());
//        byte[] IDc = Uty.xor(bankClient.getBankParameter().getBankID().getBytes(), K_1.y.toByteArray());
        byte[] IDc = Uty.xorWithKey(bankClient.getBankParameter().getBankID().getBytes(), K_1.y.toByteArray());
//        System.out.println("ID " + Arrays.toString(IDc));
//        System.out.println("Bank ID " + Arrays.toString(bankClient.getBankParameter().getBankID().getBytes()));
//        System.out.println("ID " + new String(IDc, "UTF-8"));
//        byte[] lol = Uty.xor(IDc, K_1.y.toByteArray());
//        System.out.println("lol " + new String(lol));


        byte[] h_b_data = Uty.byteConcatenate(Arrays.asList(cipherAccount,
                cipherText,
                bankClient.getBankParameter().getBankID().getBytes(),
                z_b.toString().getBytes(),
                clientInfo.getPublicKey().getXCoordinates().toString().getBytes(),
                bankClient.getBankParameter().getPublicKey().getXCoordinates().toString().getBytes(),
                bankClient.getPublicParameter().getKgcPublic().toString().getBytes()));

        BigInteger h_b = Uty.bytesHash(h_b_data);

        BigInteger S = (r_b.subtract(h_b.multiply(bankClient.getBankParameter().getPrivateKey().getXCoordinates().add
                (bankClient.getBankParameter().getPrivateKey().getYCoordinate())))).mod(bankClient.getPublicParameter().getOrder());

        ECPoint R = bankClient.getPublicParameter().getCurve().multiply(bankClient.getPublicParameter().getCurve().add
                (bankClient.getBankParameter().getPublicKey().getXCoordinates(), bankClient.getBankParameter().getPointOfBankPartialKey()), h_b);

        System.out.println("cipher is " + Arrays.toString(cipherText));
        System.out.println("z_b is " + z_b);
        System.out.println("pc1 " + clientInfo.getPublicKey().getXCoordinates());
        System.out.println("pb1 " + bankClient.getBankParameter().getPublicKey().getXCoordinates());
        System.out.println("pkgc " + bankClient.getPublicParameter().getKgcPublic());
        System.out.println("h_b is " + h_b);
        System.out.println("pc2 " + pointOfClientPartialKey(clientInfo));
        System.out.println("R is " + R);
        System.out.println("S is " + S);

        HashMap<String, Object>  hshMap = new HashMap<>();
        hshMap.put("S", S);
        hshMap.put("R", R);
        hshMap.put("c", cipherText);
        System.out.println("Cipher " + cipherText);
        hshMap.put("ACC", cipherAccount);

        return hshMap;
    }

    public byte[] unSigncryption(HashMap<String, Object> HashMap) throws IOException {

//        System.out.println("r_x " + HashMap.get("r_x"));
//        BigInteger r_x = new BigInteger(1, HashMap.get("r_x"));
//        BigInteger r_y = new BigInteger(1, HashMap.get("r_y"));
//        BigInteger Sr = new BigInteger(1, HashMap.get("s"));
//        System.out.println("Cipher " + HashMap.get("c"));
//
//        ECPoint Rr = new ECPoint(r_x, r_y);

        BigInteger Sr = (BigInteger)HashMap.get("S");
        ECPoint Rr = (ECPoint) HashMap.get("R");

        ECPoint z_sb = bankClient.getPublicParameter().getCurve().add(bankClient.getPublicParameter().getCurve().multiply
                (bankClient.getPublicParameter().getBasePoint(), Sr), Rr);

        ECPoint K_1b = bankClient.getPublicParameter().getCurve().multiply(z_sb, bankClient.getBankParameter().getPrivateKey().getYCoordinate());

        System.out.println("K_1b " + K_1b);

        byte[] cipherAccount = Uty.xorWithKey((byte[])HashMap.get("ACC"), K_1b.y.toByteArray());

        HashMap<String, Object> AccountHshMap = byteToMap(cipherAccount);

        if(Uty.currentDate().compareTo((String) AccountHshMap.get("t"))<0)
            return null;

        String receivedID = (String) AccountHshMap.get("IDC");


//        byte[] IDcBc = Uty.xorWithKey(HashMap.get("IDcB"), K_1b.y.toByteArray());
//        String receivedID = new String(IDcBc);
        System.out.println("receivedID " + receivedID);
//
        if (receivedID == null)
            return null;

        Clients clientInfo = bankClient.clientIDCheck(receivedID);

        if (clientInfo.getPublicKey() == null)
            return null;

//        if (receivedID != null) {
//            clientInfo = bankClient.clientIDCheck(receivedID);
//        } else {
//            System.out.println("receivedID is null ");
//        }



        byte[] plainText = null;
            byte[] h_b_data = Uty.byteConcatenate(Arrays.asList((byte[])HashMap.get("ACC"),
                    (byte[])HashMap.get("c"),
                    clientInfo.getClientID().getBytes(),
                    z_sb.toString().getBytes(),
                    clientInfo.getPublicKey().getXCoordinates().toString().getBytes(),
                    bankClient.getBankParameter().getPublicKey().getXCoordinates().toString().getBytes(),
                    bankClient.getPublicParameter().getKgcPublic().toString().getBytes()));

        System.out.println("cipherAccount " + Arrays.toString(cipherAccount));
        System.out.println("cipherText " + Arrays.toString( (byte[])HashMap.get("c")));
        System.out.println("z_sb " + z_sb);
        System.out.println("ClientID() " + clientInfo.getClientID());
        System.out.println("pc1 " + clientInfo.getPublicKey().getXCoordinates());
        System.out.println("pb1 " + bankClient.getBankParameter().getPublicKey().getXCoordinates());
        System.out.println("pkgc " +bankClient.getPublicParameter().getKgcPublic());

            BigInteger h_b = Uty.bytesHash(h_b_data);

            p_C2 = pointOfClientPartialKey(clientInfo);

            ECPoint R_b = bankClient.getPublicParameter().getCurve()
                    .multiply(bankClient.getPublicParameter().getCurve()
                            .add(clientInfo.getPublicKey().getXCoordinates(),
                                    p_C2),
                            h_b);

            System.out.println("cipher is " + Arrays.toString((byte[])HashMap.get("c")));
            System.out.println("z_sb is " + z_sb);
            System.out.println("clientInfo.getPublicKey().getXCoordinates() is " + clientInfo.getPublicKey().getXCoordinates());
            System.out.println("bankClient.getBankParameter().getPublicKey().getXCoordinates() is " + bankClient.getBankParameter().getPublicKey().getXCoordinates());
            System.out.println("bankClient.getPublicParameter().getKgcPublic() is " + bankClient.getPublicParameter().getKgcPublic());
            System.out.println("h_b is " + h_b);
            System.out.println("pointOfClientPartialKey is " + p_C2);
            System.out.println("R_b is " + R_b);
            System.out.println("Rr is " + Rr);
//            plainText = null;

            if (R_b.toString().equals(Rr.toString())) {
                System.out.println("Is Equal");
                byte[] receivedKey = K_1b.x.toByteArray();
                plainText = Uty.xorWithKey((byte[])HashMap.get("c"), receivedKey);
            }
        System.out.println("plainText is " + Arrays.toString(plainText));
        return plainText;
    }

    private ECPoint pointOfClientPartialKey() {
        byte[] h_c_data = Uty.byteConcatenate(Arrays.asList(this.bankClient.getClientParameter().getClientID().getBytes(),
                this.bankClient.getPublicParameter().getKgcPublic().toString().getBytes(),
                this.bankClient.getClientParameter().getPublicKey().getYCoordinate().toString().getBytes(),
                this.bankClient.getClientParameter().getPublicKey().getXCoordinates().toString().getBytes()));

        BigInteger h_c = Uty.bytesHash(h_c_data);
        this.p_C2 = this.bankClient.getPublicParameter().getCurve().add(this.bankClient.getClientParameter().getPublicKey().getYCoordinate(), this.bankClient.getPublicParameter().getCurve().multiply(this.bankClient.getPublicParameter().getKgcPublic(), h_c));
        return this.p_C2;
    }
//    private ECPoint pointOfClientPartialKey() {
//        byte[] h_c_data = Uty.byteConcatenate(Arrays.asList(bankClient.getClientParameter().getClientID().getBytes(),
//                bankClient.getPublicParameter().getKgcPublic().toString().getBytes(),
//                bankClient.getClientParameter().getPublicKey().getYCoordinate().toString().getBytes(),
//                bankClient.getClientParameter().getPublicKey().getXCoordinates().toString().getBytes()));
//        BigInteger h_c = Uty.bytesHash(h_c_data);
//
//        p_C2 = bankClient.getPublicParameter().getCurve().add( bankClient.getClientParameter().getPublicKey().getYCoordinate(),
//                bankClient.getPublicParameter().getCurve().multiply(bankClient.getPublicParameter().getKgcPublic(), h_c));
//
//        return p_C2;
//    }
    private ECPoint pointOfClientPartialKey(Clients clientInfo) {
        byte[] h_c_data = Uty.byteConcatenate(Arrays.asList(clientInfo.getClientID().getBytes(),
                bankClient.getPublicParameter().getKgcPublic().toString().getBytes(),
                clientInfo.getPublicKey().getYCoordinate().toString().getBytes(),
                clientInfo.getPublicKey().getXCoordinates().toString().getBytes()));
        BigInteger h_c = Uty.bytesHash(h_c_data);

        p_C2 = bankClient.getPublicParameter().getCurve().add( clientInfo.getPublicKey().getYCoordinate(),
                bankClient.getPublicParameter().getCurve().multiply(bankClient.getPublicParameter().getKgcPublic(), h_c));

        return p_C2;
    }

    public static String extract(String stegImage) {
        BufferedImage stego = null;
        try {
//            stego = ImageIO.read(new File(stegImage));

            InputStream is = new BufferedInputStream(
                    new FileInputStream(stegImage));
            stego = ImageIO.read(is);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return Extracting.extractSecretMessage(stego);
    }

    public static void embed(String serialized, File srcImage, File outImageFilePath) {
        BufferedImage original = null;
        try {
//            original = ImageIO.read(new File(srcImage));
            original = ImageIO.read(srcImage);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (original == null) {
            System.out.println("Original is null");
            return;
        }
        BufferedImage encodedText = Embedding.embedSecretText(serialized, original);

        try {
            ImageIO.write(encodedText, "png", outImageFilePath );
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
