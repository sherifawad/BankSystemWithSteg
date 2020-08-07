import algorithm.ecc.ECPoint;
import algorithm.encryption.AESencryption;
import connection.Message;
import parameters.Clients;
import parameters.PublicKey;
import parameters.publicParameters;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;


public class ServerWorker extends Thread{
    private final Server server;
    private Socket clientSocket;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private publicParameters publicParameters;
    private ServerWorker worker;


    public ServerWorker(Server server, Socket clientSocket, publicParameters publicParameters) {
        this.server = server;
        this.clientSocket = clientSocket;
        this.publicParameters = publicParameters;
    }

    @Override
    public void run() {
        handleClientSocket();
    }

    public static void removeWorker(ServerWorker serverWorker) {
        workerList.remove(serverWorker);
    }

    public ServerWorker getWorker() {
        return worker;
    }

    public ArrayList<ServerWorker> getWorkerList() {
        return workerList;
    }

    private static ArrayList<ServerWorker> workerList = new ArrayList<>();

    private void handleClientSocket() {
        try {
            this.clientSocket = clientSocket;
            this.objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            this.objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
            startMessageReader();
        } catch (IOException e) {
            server.removeWorker(this);
            System.out.println(e.getMessage());
        }
    }

    private void startMessageReader() {
        System.out.println("Start message Reading Loop");
        Message message;
        try {
//            Message message = Message.class.cast(objectInputStream.readObject());
//            while (message != null){
            while ((message = Message.class.cast(objectInputStream.readObject())) != null){
                try {
                String cmd = message.getCommand();
                if ("public".equalsIgnoreCase(cmd)) {
                    System.out.println("public command received");
                    handlePublicParameters(message.getClientID());
                } else if ("auth".equalsIgnoreCase(cmd)) {
                    System.out.println("Auth command received");
                    System.out.println("Auth Body " + (byte[]) message.getMessageBody());
                    handleAuthentication(message.getClientID(), null, (byte[]) message.getMessageBody());
                } else if ("client".equalsIgnoreCase(cmd)) {
                    handleClientInfo((String) message.getMessageBody());
                }  else {
                    send("Error", "UnknownCommand");
                }
                } catch (IOException e) {
                    System.out.println("ERR ERR ERR ERR");
                    send("Error", "FormatError");
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    private void handleAuthentication(String clientID, ECPoint publickey, byte[] messageBody) throws IOException {
        boolean exist = false;
        for(Clients client : server.getClientsList()) {
            if (!(clientID.equals(client.getClientID()))) {
                continue;
            }else {
                byte[] gcmDecryption = null;
                    System.out.println("pass " + Arrays.toString(client.getPassword()));

                    gcmDecryption = AESencryption.gcmMode(Cipher.DECRYPT_MODE,
                            client.getClientID().getBytes(),
                            client.getPassword(),
                            messageBody);

                    //                gcmDecryption = AESencryption.gcmMode(Cipher.DECRYPT_MODE,
                    //                        "51".getBytes(),
                    //                        "a2".toCharArray(),
                    //                        messageBody);

                try {
                    //                    String accountNumber = "";
                    //                    System.out.println("clientID " + client.getClientID());

                    if (gcmDecryption == null) {
                        send("ErrorAuth", "Wrong Password");
                        System.out.println("Auth Error");
                        return;
                    }

                    HashMap<String, Object> ReceivedAccountHshMap = Uty.byteTOMap(gcmDecryption);
                    String t = (String) (ReceivedAccountHshMap.get("t"));
                    System.out.println("t equal " + t);
                    System.out.println("current date " + Uty.currentDate());

                    if (Uty.currentDate().compareTo(t) < 0) {
                        System.out.println("Wrong time message is duplicated");
                        return;
                    }
                    if ((int) (ReceivedAccountHshMap.get("name")) != ((client.getName().hashCode()))) {
                        System.out.println("Wrong user name");
                        return;
                    }
                    if (ReceivedAccountHshMap.get("pc1") == null) {
                        System.out.println("PC1 is null");
                        return;
                    }
                    try {
                        publickey = (ECPoint) (ReceivedAccountHshMap.get("pc1"));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    if (publickey == null) {
                        System.out.println("Public Key is Null");
                        return;
                    }
                        authenticationProcess(publickey, client);

                } catch (Exception e) {
                    e.printStackTrace();
                }
                exist =true;
                break;
            }
        }
        if (!exist)
            send("ErrorAuth", "UnknownID");
    }

    private void handlePublicParameters(String clientID){
        for (Clients client : server.getClientsList()){
            System.out.printf("clients" + client);
            if (clientID.equals(client.getClientID())) {
                System.out.println("clientID " + clientID);
                if (client.getPublicKey() !=null) {
                    send("public", publicParameters);
                } else {
                    send("publicU", publicParameters);
                }
                client.setAddress(this.getAddress());
                client.setPort(this.getPort());
                break;
            }
        }
    }

    private void handleClientInfo(String accountNumber){
        for (Clients client : server.getClientsList()){
            if (accountNumber.equals(client.getAccountNumber())) {
                send("Client", client);
                break;
            }else {
                send("Error", "UnknownClient");
            }
        }
    }

    private void authenticationProcess( ECPoint publickey, Clients client) {
            BigInteger r_KGC;
//            do {
//                r_KGC = Uty.randomBig(publicParameters.getOrder());
//            } while (r_KGC == null);
//            System.out.println("client r_KGC " + r_KGC);
            r_KGC = new BigInteger("2480450336757088487282759606031095470115102398875");
            ECPoint R_KGC = publicParameters.getCurve().multiply(publicParameters.getCurve().getBasePoint(), r_KGC);
            System.out.println("R_KGC " + R_KGC);

            byte[] concatenateClient = Uty.byteConcatenate(Arrays.asList(client.getClientID().getBytes(),
                    publicParameters.getKgcPublic().toString().getBytes(), R_KGC.toString().getBytes(), publickey.toString().getBytes()));
            BigInteger hashClient = Uty.bytesHash(concatenateClient);
            System.out.println("concatenateClient " + concatenateClient);

            BigInteger partialKey = (r_KGC.add(server.getPrivate().multiply(hashClient))).mod(publicParameters.getOrder());
            System.out.println("partialKey " + partialKey);


            System.out.println("creating Hash Map");
            HashMap<String, Object> hashMap =new HashMap<>();
            hashMap.put("t", Uty.currentDate());
            hashMap.put("PartialKey", partialKey);
            hashMap.put("PublicKey_YCoordinate", R_KGC);
            byte[] mapTOBytes = Uty.mapTOBytes(hashMap);

            try {
                System.out.println(" encrypte the map");

                byte[] cipher = (AESencryption.gcmMode(Cipher.ENCRYPT_MODE,
                        client.getClientID().getBytes(),
                        client.getPassword(),
                        mapTOBytes));

//                byte[] cipher = (AESencryption.gcmMode(Cipher.ENCRYPT_MODE,
//                        "51".getBytes(),
//                        "a2".toCharArray(),
//                        mapTOBytes));

                System.out.println("try to send the cipher");
                send("Key", cipher);
                System.out.println("Cipher has been send");
                PublicKey fullPublicKey = new PublicKey(publickey, R_KGC);
                client.setPublicKey(fullPublicKey);
            } catch (Exception e) {
                System.out.println("message " + e.getMessage());
                e.printStackTrace();
            }
    }

    public void send(String Command, Object messageBody) {
        Message message = new Message(Command, "KGCServer", publicParameters.getKgcPublic(), messageBody);
        try {
                objectOutputStream.writeObject(message);
                objectOutputStream.flush();
        } catch(Exception ex) {
                ex.printStackTrace();
        }
    }

    public InetAddress getAddress() {
        return this.clientSocket.getInetAddress();
    }

    public int getPort() {
        return this.clientSocket.getPort();
    }

    public void close(){
        try {
            if (objectOutputStream != null) {
                objectOutputStream.close();
            }
            if (objectInputStream != null) {
                objectInputStream.close();
            }
//            if (clientSocket != null) {
//                clientSocket.close();
//            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
