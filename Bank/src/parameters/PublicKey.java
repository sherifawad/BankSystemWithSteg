package parameters;

import algorithm.ecc.ECPoint;

import java.io.Serializable;

public class PublicKey implements Serializable{
    private static final long serialVersionUID = 539475L;

    private ECPoint xCoordinates;
    private  ECPoint yCoordinate;

    public ECPoint getXCoordinates() {
        return xCoordinates;
    }

    public ECPoint getYCoordinate() {
        return yCoordinate;
    }


    @Override
    public String toString() {
        return "PublicKey{" + "xCoordinates=" + xCoordinates + ", yCoordinate=" + yCoordinate + '}';
    }

    public PublicKey(ECPoint XCoordinates, ECPoint YCoordinate) {

        this.xCoordinates = XCoordinates;
        this.yCoordinate = YCoordinate;
    }


    public boolean equal(PublicKey o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return this.xCoordinates.equal(o.xCoordinates) &&
                this.yCoordinate.equal(o.yCoordinate);
    }
}