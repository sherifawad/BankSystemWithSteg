package parameters;

import algorithm.ecc.ECPoint;

import java.net.InetAddress;

public class Bank {

    private String bankID;
    private InetAddress bankAddress;
    private int bankPort;
    private PrivateKey privateKey;
    private static PublicKey publicKey ;
    private ECPoint pointOfBankPartialKey;

    public Bank() {
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public ECPoint getPointOfBankPartialKey() {
        return pointOfBankPartialKey;
    }

    public void setPointOfBankPartialKey(ECPoint pointOfBankPartialKey) {
        this.pointOfBankPartialKey = pointOfBankPartialKey;
    }

    public Bank(PrivateKey privateKey, final PublicKey publicKey, ECPoint pointOfBankPartialKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.pointOfBankPartialKey = pointOfBankPartialKey;
    }

    public InetAddress getBankAddress() {
        return bankAddress;
    }

    public int getBankPort() {
        return bankPort;
    }

    public String getBankID() {
        return bankID;
    }

    public Bank(final String bankID, final InetAddress bankAddress, final int bankPort) {
        this.bankID = bankID;
        this.bankAddress = bankAddress;
        this.bankPort = bankPort;
    }

}

