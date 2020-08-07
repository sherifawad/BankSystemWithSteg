package algorithm.ecc;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * This class will represent a point inside an elliptic curve.

 */
public class ECPoint implements Serializable {
    public BigInteger x;
    public BigInteger y;
    private boolean pointOfInfinity;

    public ECPoint() {
        this.x = this.y = BigInteger.ZERO;
        this.pointOfInfinity = false;
    }

    public ECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
        this.pointOfInfinity = false;
    }

    public ECPoint(long x, long y) {
        this.x = BigInteger.valueOf(x);
        this.y = BigInteger.valueOf(y);
        this.pointOfInfinity = false;
    }

    public ECPoint(ECPoint p) {
        this.x = p.x;
        this.y = p.y;
        this.pointOfInfinity = p.pointOfInfinity;
    }


    public boolean isPointOfInfinity() {
        return pointOfInfinity;
    }

    public ECPoint negate() {
        if (isPointOfInfinity()) {
            return INFINTIY;
        } else {
            return new ECPoint(x, y.negate());
        }
    }

    private static ECPoint infinity() {
        ECPoint point = new ECPoint();
        point.pointOfInfinity = true;
        return point;
    }

    public static final ECPoint INFINTIY = infinity();

    @Override
    public String toString() {
        if (isPointOfInfinity()) {
            return "INFINITY";
        } else {
            return "(" + x.toString() + ", " + y.toString() + ")";
        }
    }

    public String toString(int radix) {
        if (isPointOfInfinity()) {
            return "INFINITY";
        } else {
            return "(" + x.toString(radix) + ", " + y.toString(radix) + ")";
        }
    }

    public boolean equal(ECPoint o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.pointOfInfinity == o.pointOfInfinity &&
                this.x.equals(o.x) &&
                this.y.equals(o.y);
    }
}
