import algorithm.ecc.ECPoint;
import connection.Message;
import parameters.Clients;
import parameters.PublicKey;
import parameters.publicParameters;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;


public class BankConnection extends Thread{
    private final Server server;
    private final int serverPort;
    private final parameters.publicParameters publicParameters;
    private boolean serverStatus;
    private final static int bankPORT = 6541;
    private final static String bankADDRESS = "localhost";
    private ServerSocket serverToBankSocket;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private Socket socket;

    public BankConnection(Server server, int serverPort, publicParameters publicParameters, boolean serverStatus) {
        this.server = server;
        this.serverPort = serverPort;
        this.publicParameters = publicParameters;
        this.serverStatus = serverStatus;
    }

    @Override
    public void run() {
        try {
            serverToBankSocket = new ServerSocket(serverPort);
            while (serverStatus) {
                System.out.println("Ready to accept from Bank");
                this.socket = serverToBankSocket.accept();
                this.objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                this.objectInputStream = new ObjectInputStream(socket.getInputStream());
                System.out.println(socket.getInetAddress());
                System.out.println(socket.getPort());
                readMessageLoop();

//                startMessageReader();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void send(String Command, Object messageBody){
        Message message;
        message = new Message(Command, "KGCServer", publicParameters.getKgcPublic(), messageBody);
        try {
            objectOutputStream.writeObject(message);
            objectOutputStream.flush();
            System.out.println(" Send Message " + message.toString());
        } catch(Exception ex) {
//            server.acceptClients(false);
            ex.printStackTrace();
        }
    }

    private void startMessageReader() {
        Thread t = new Thread("MessageReader") {
            @Override
            public void run() {
                readMessageLoop();
            }
        };
        t.start();
    }

    private void readMessageLoop(){
        Message message;
        try {
            Server.bankConnected = true;
            while ((message = Message.class.cast(objectInputStream.readObject())) != null){
                System.out.println("Received connection.Message " + message.toString());
                try {
                    String cmd = message.getCommand();
                    if ("public".equalsIgnoreCase(cmd)) {
                        System.out.println("Public Command Received");
                        handlepublicParameters(message);
                    } else if ("key".equalsIgnoreCase(cmd)) {
                        System.out.println("key Command Received");
                        handleKeyGeneration(message);
                    } else if ("clientID".equalsIgnoreCase(cmd)) {
                        System.out.println("client Command Received");
                        handleClientID((String) message.getMessageBody());
                    } else if ("clientAccountNumber".equalsIgnoreCase(cmd)) {
                        System.out.println("client Command Received");
                        handleClientAccountNumber((String) message.getMessageBody());
                    }  else if ("Error".equalsIgnoreCase(cmd)) {
                        handleErrorMessages(message);
                        System.out.println("client Command Received");
                    } else {
                        System.out.println("CommandError");
                        send("Error", "CommandError");
                    }
                } catch (IOException e) {
                    send("Error", "FormatError");
                    System.out.println("FormatError");
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            Server.bankConnected = false;
            publicParameters.setBankPublicKey(null);
            publicParameters.setBankAddress(null);
            e.printStackTrace();
        }

    }

    private void handleClientID(String clientID) {
        List<Clients> clientsList = server.getClientsList();
        for (Clients client : clientsList){
            if (!(clientID.equals(client.getClientID())))
                continue;

            send("Client", client);
            break;
        }
    }

    private void handleClientAccountNumber(String accountNumber) {

       boolean exist = false;
        List<Clients> clientsList = server.getClientsList();

//        for (int i = 0; i < clientsList.size(); i++) {
//            if (accountNumber.equals(clientsList.get(i).getAccountNumber())) {
//                send("Client", clientsList.get(i));
//                break;
//        }
//        for (Clients client : clientsList){
//            if (accountNumber.equals(client.getAccountNumber())) {
//                send("Client", client);
//                break;
//            }else {
//                send("Error", "UnknownClient");
//                break;
//            }
//        }

        for (Clients client : clientsList){
            if (!accountNumber.equals(client.getAccountNumber())) {
                continue;
            }else {
                send("Client", client);
                exist =true;
                break;
            }
        }
        if (!exist) {
            send("Error", "UnknownClient");
        }
    }

    private void handleErrorMessages(Message message) {
        System.out.println("-------------------");
        System.out.println("ID " + message.getClientID());
        System.out.println("PublicKey " + message.getPublicKey());
        System.out.println("MessageBody " + message.getMessageBody());
        System.out.println("-------------------");
    }

    private void handleClientInfo(String clientInfo) throws IOException {
        boolean bool = isNumeric(clientInfo);
        boolean exist = false;
        System.out.println("Bool " + bool);
        List<Clients> clientsList = server.getClientsList();
        if (bool) {
            for (Clients client : clientsList){
                if (!clientInfo.equals(client.getAccountNumber())) {
                    continue;
                }else {
                    send("Client", client);
                    exist =true;
                    break;
                }
            }
        } else {
            for (Clients client : clientsList){
                if (!clientInfo.equals(client.getClientID())) {
                    continue;
                }else {
                    send("Client", client);
                    exist =true;
                    break;
                }
            }
        }
        if (!exist) {
            send("Error", "UnknownClient");
        }
    }

    private boolean isNumeric(String str)
    {
        try
        {
            BigInteger d =  new BigInteger(str);
        }
        catch(NumberFormatException nfe)
        {
            return false;
        }
        return true;
    }

    private void handleKeyGeneration(Message message) throws IOException {

        BigInteger r_KGC;
//        do {
//            r_KGC = Uty.randomBig(publicParameters.getOrder());
//        } while (r_KGC == null);
//        System.out.println("Bank r_KGC " + r_KGC);

        r_KGC = new BigInteger("1120176766045631264898668350787047449376577213723");

        ECPoint R_KGC = publicParameters.getCurve().multiply(publicParameters.getCurve().getBasePoint(), r_KGC);
        byte[] concatenateClient = Uty.byteConcatenate(Arrays.asList(message.getClientID().getBytes(),
                publicParameters.getKgcPublic().toString().getBytes(), R_KGC.toString().getBytes(), ((ECPoint)message.getPublicKey()).toString().getBytes()));
        BigInteger hashClient = Uty.bytesHash(concatenateClient);
        BigInteger partialKey = (r_KGC.add(Server.getPrivate().multiply(hashClient))).mod(publicParameters.getOrder());
        PublicKey fullPublicKey = new PublicKey((ECPoint)message.getPublicKey(), R_KGC);

        sendGeneratedKeys(R_KGC, partialKey);
        setBankParameters(message, fullPublicKey);
//        server.acceptClients(true);

    }

    private void sendGeneratedKeys(ECPoint r_KGC, BigInteger partialKey) {
        HashMap<String, Object> hashMap = new HashMap<>();
        hashMap.put("partialKey", partialKey);
        hashMap.put("generatedPartialPublic", r_KGC);
        send("Key", hashMap);
    }

    private void setBankParameters(Message message, PublicKey fullPublicKey) {
        publicParameters.setBankID(message.getClientID());
        HashMap<String, Object> hashMap = (HashMap<String, Object>) message.getMessageBody();
        InetAddress bankAddress = (InetAddress) hashMap.get("Address");
        int bankPort = (int) hashMap.get("Port");
        publicParameters.setBankAddress(bankAddress);
        publicParameters.setBankPort(bankPort);
        publicParameters.setBankPublicKey(fullPublicKey);
        System.out.println("BankPublicKey " + publicParameters.getBankPublicKey());
    }

    private void handlepublicParameters(Message message) throws IOException {
        send("public", publicParameters);
    }
}
