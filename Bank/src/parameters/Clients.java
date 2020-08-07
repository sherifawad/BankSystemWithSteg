package parameters;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;

public class Clients implements Serializable{
    private static final long serialVersionUID = 3216446;


    private String  accountNumber;
    private  String name;
    private  char[] password;
    private  InetAddress address;
    private  int port;
    private  String clientID;
    private PublicKey publicKey;
    private static ArrayList<Clients> clientsList = new ArrayList<>();



    public Clients() {
    }

    public String getName() {
        return name;
    }

    public char[] getPassword() {
        return password;
    }

    public InetAddress getAddress() {
        return address;
    }

    public void setAddress(InetAddress address) {
        this.address = address;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getClientID() {
        return clientID;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String  getAccountNumber() {
        return accountNumber;
    }

    @Override
    public String toString() {
        return "Clients{" + "accountNumber='" + accountNumber + '\'' + ", name='" + name + '\'' + ", password=" + Arrays.toString(password) + ", address=" + address + ", port=" + port + ", clientID='" + clientID + '\'' + ", publicKey=" + publicKey + '}';
    }

    public Clients(final String  accountNumber, String name, char[] password , InetAddress address, int port, final String clientID, final PublicKey publicKey) {
        this.accountNumber = accountNumber;
        this.name = name;
        this.password = password;
        this.address = address;
        this.port = port;
        this.clientID = clientID;
        this.publicKey = publicKey;
    }

}

