package parameters;

import algorithm.ecc.ECPoint;
import algorithm.ecc.EllipticCurve;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.InetAddress;

public class publicParameters implements Serializable {
    private static final long serialVersionUID = 539896475L;

    private EllipticCurve curve;
    private ECPoint basePoint;
    private BigInteger order;
    private ECPoint kgcPublic;
    private String bankID;
    private InetAddress bankAddress;
    private int bankPort;
    private PublicKey bankPublicKey;

    public publicParameters() {
    }

    public EllipticCurve getCurve() {
        return curve;
    }

    public ECPoint getBasePoint() {
        return basePoint;
    }

    public BigInteger getOrder() {
        return order;
    }

    public ECPoint getKgcPublic() {
        return kgcPublic;
    }

    public String getBankID() {
        return bankID;
    }

    public InetAddress getBankAddress() {
        return bankAddress;
    }

    public int getBankPort() {
        return bankPort;
    }

    public PublicKey getBankPublicKey() {
        return bankPublicKey;
    }

    @Override
    public String toString() {
        return "publicParameters{" + "curve=" + curve + ", basePoint=" + basePoint + ", order=" + order + "," +
                " kgcPublic=" + kgcPublic + ", bankID='" + bankID + '\'' + ", bankAddress=" + bankAddress + "," +
                " bankPort=" + bankPort + ", bankPublicKey=" + bankPublicKey + '}';
    }

    public publicParameters(EllipticCurve Curve, ECPoint basePoint, BigInteger Order, ECPoint KGCPublic,
                            String BankID, InetAddress BankAddress, int BankPort, PublicKey bankPublicKey) {
        this.curve = Curve;
        this.basePoint = basePoint;
        this.order = Order;
        this.kgcPublic = KGCPublic;
        this.bankID = BankID;
        this.bankAddress = BankAddress;
        this.bankPort = BankPort;
        this.bankPublicKey = bankPublicKey;
    }

    public void setCurve(EllipticCurve curve) {
        this.curve = curve;
    }

    public void setBasePoint(ECPoint basePoint) {
        this.basePoint = basePoint;
    }

    public void setOrder(BigInteger order) {
        this.order = order;
    }

    public void setKgcPublic(ECPoint kgcPublic) {
        this.kgcPublic = kgcPublic;
    }

    public void setBankID(String bankID) {
        this.bankID = bankID;
    }

    public void setBankAddress(InetAddress bankAddress) {
        this.bankAddress = bankAddress;
    }

    public void setBankPort(int bankPort) {
        this.bankPort = bankPort;
    }

    public void setBankPublicKey(PublicKey bankPublicKey) {
        this.bankPublicKey = bankPublicKey;
    }


    public boolean equal(publicParameters o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
//        publicParameters that = (publicParameters) o;
        return this.bankPort == o.bankPort &&
                this.curve.equal(o.curve) &&
                this.basePoint.equal(o.basePoint) &&
                this.order.equals(o.order) &&
                this.kgcPublic.equal(o.kgcPublic) &&
                this.bankID.equals(o.bankID) &&
                this.bankAddress.equals(o.bankAddress) &&
                this.bankPublicKey.equal(o.bankPublicKey);
    }
}