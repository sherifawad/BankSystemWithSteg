package connection;

import Util.Uty;
import algorithm.ecc.ECPoint;
import parameters.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashMap;

public class BankServer extends Thread{
    private parameters.publicParameters publicParameters;
    private  int serverPort;
    private  String localAddr;
    private  int localPort;
    private  String serverName;
    private BigInteger n, d_B;
    private ECPoint P_B;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private Socket toServersSocket;
    private Bank bank;
    private Clients client;

    public BankServer(){
    }

    public BankServer(String serverName, int serverPort) {
        this.serverName = serverName;
        this.serverPort = serverPort;
    }


    public void run() {
        try {
            bank = new Bank("Bank_Identity_66246552", InetAddress.getByName("localhost"), 4444);
//            bank = new Bank("Bank_Identity_66246552", InetAddress.getByName("192.168.1.135"), 4444);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        handleKGCServer();
    }

    public void handleKGCServer() {
        try {
            this.toServersSocket = new Socket(serverName, serverPort);
            this.objectOutputStream = new ObjectOutputStream(toServersSocket.getOutputStream());
            this.objectInputStream = new ObjectInputStream(toServersSocket.getInputStream());
            process();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void process() {
        send("Public", null);
        startMessageReader();
//        readMessageLoop();
    }

    private void bankKeyGeneration(){

        do {
            try {
//                do {
//                    d_B = Uty.randomBig(publicParameters.getOrder());
//                } while (d_B == null);
//                System.out.println("d_B " + d_B);

                d_B = new BigInteger("247445952918018622471015468821956594730263769882");
                P_B = publicParameters.getCurve().multiply(publicParameters.getBasePoint(), d_B);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        } while (P_B.isPointOfInfinity() || publicParameters.getBasePoint() == P_B  || P_B == new ECPoint(0, 0));
        generationProcess();
    }

    public ECPoint getPartialPublicKey() {
        return P_B;
    }

    public BigInteger getPrivate() {
        return d_B;
    }

    private void send(String Command, Object messageBody){
        Message message;
        if (bank.getPublicKey() != null) {
            message = new Message(Command, bank.getBankID(), bank.getPublicKey(), messageBody);
        } else if (this.getPartialPublicKey() != null){
            message = new Message(Command, bank.getBankID(), this.getPartialPublicKey(), messageBody);
        } else {
            message = new Message(Command, bank.getBankID(), null, messageBody);
        }
        System.out.println("send Message " + message.toString());
        try {
            objectOutputStream.writeObject(message);
            objectOutputStream.flush();
            System.out.println("Message has been send");
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }

    private void startMessageReader() {
        Thread t = new Thread("MessageReader") {
            @Override
            public void run() {
                System.out.println("message thread");
                readMessageLoop();
            }
        };
        t.start();
    }

    private void readMessageLoop() {
        Message message;
        try {
            while ((message = Message.class.cast(objectInputStream.readObject())) != null){
                try {
                    String cmd = message.getCommand();
                    if ("public".equalsIgnoreCase(cmd)) {
                        System.out.println("Public Command Received");
                        handlePublicParameters(message);
                    } else if ("key".equalsIgnoreCase(cmd)) {
                        System.out.println("key Command Received");
                        handleKeyGeneration(message);
                    } else if ("client".equalsIgnoreCase(cmd)) {
                        System.out.println("client Command Received");
                        handleClientInfo((Clients) message.getMessageBody());
                    }   else if ("Error".equalsIgnoreCase(cmd)) {
                        handleErrorMessages(message);
                    } else {
//                        send("Error", "CommandError");
                        System.out.println("CommandError");
                        send("Error", "CommandError");
                    }
                } catch (IOException e) {
//                    send("Error", "FormatError");
                    System.out.println("FormatError");

                }
            }
            try {
                toServersSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }

    private void handleErrorMessages(Message message) {
        System.out.println("-------------------");
        System.out.println("ID " + message.getClientID());
        System.out.println("PublicKey " + message.getPublicKey());
        System.out.println("MessageBody " + message.getMessageBody());
        System.out.println("-------------------");
    }

    public  void handleClientInfo(Clients clientInfo) throws IOException {
        client = clientInfo;
    }

    private void handleKeyGeneration(Message message) throws IOException {
        HashMap<String, Object> hashMap = ((HashMap<String, Object>) message.getMessageBody());
        BigInteger partialKey =  (BigInteger)hashMap.get("partialKey");
        PrivateKey fullPrivateKey = new PrivateKey(this.getPrivate(),partialKey);
        PublicKey fullPublicKey = new PublicKey(this.getPartialPublicKey(), (ECPoint) hashMap.get("generatedPartialPublic"));
        bank.setPrivateKey(fullPrivateKey);
        bank.setPublicKey(fullPublicKey);
        pointOfBankPartialKey(partialKey);
    }

    private void generationProcess()  {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("Address", bank.getBankAddress());
        hashMap.put("Port", bank.getBankPort());
        send("Key", hashMap);
    }

    private void handlePublicParameters(Message message) {
        if ("KGCServer".equalsIgnoreCase(message.getClientID())) {
            try {
                publicParameters = new publicParameters();
                publicParameters = publicParameters.getClass().cast(message.getMessageBody());

                bankKeyGeneration();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void pointOfBankPartialKey(BigInteger partialPrivateKey) {
        ECPoint p_b2 = publicParameters.getCurve().multiply(publicParameters.getBasePoint(), partialPrivateKey);
        bank.setPointOfBankPartialKey(p_b2);
    }

    public parameters.publicParameters getPublicParameter() {
        return publicParameters;
    }

    public Bank getBankParameter() {
        return bank;
    }

    public Clients getClientParameter() {
        return client;
    }

    public Clients clientIDCheck(String clientID) {
        send("clientID", clientID);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("Client " + client);
        return client;
    }
    public Clients ClientAccountNumber(String accountNumber) {
        System.out.println("accountNumber" + accountNumber);
        send("clientAccountNumber", accountNumber);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("Client " + client);
        return client;
    }
}
