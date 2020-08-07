package parameters;

import java.io.Serializable;
import java.math.BigInteger;

public class PrivateKey implements Serializable {
    private static final long serialVersionUID = 539479895L;
    private BigInteger xCoordinates;
    private  BigInteger yCoordinate;

    public BigInteger getXCoordinates() {
        return xCoordinates;
    }

    public BigInteger getYCoordinate() {
        return yCoordinate;
    }


    @Override
    public String toString() {
        return "PrivateKey{" + "xCoordinates=" + xCoordinates + ", yCoordinate=" + yCoordinate + '}';
    }

    public PrivateKey(BigInteger XCoordinates, BigInteger YCoordinate) {

        this.xCoordinates = XCoordinates;
        this.yCoordinate = YCoordinate;
    }

    public boolean equal(PrivateKey o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.xCoordinates.equals(o.xCoordinates) &&
                this.yCoordinate.equals(o.yCoordinate);
    }

}