import algorithm.ecc.ECPoint;
import algorithm.ecc.EllipticCurve;
import parameters.Clients;
import parameters.publicParameters;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Server extends Thread{
    private publicParameters publicParameters = new publicParameters();
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private  int serverPort;
    private boolean Running = false;
    private Scanner scanner;
    private static BigInteger d_KGC;
    private Clients client;
    private static ArrayList<Clients> clientsList = new ArrayList<>();
    public static boolean bankConnected;
    private ClientConnection clientConnection;
    private Thread newParameters;
    private BankConnection bankConnection;
    private ServerSocket serverSocket;
    private ServerWorker worker;


    public Server(int serverPort) {
        this.serverPort = serverPort;
    }

    public Server() {
    }



    public List<ServerWorker> getWorkerList() {
        return workerList;
    }

    public List<Clients> getClientsList() {
        return clientsList;
    }
    public  void removeWorker(ServerWorker serverWorker) {
        workerList.remove(serverWorker);
    }



    @Override
    public void run() {
        scanner = new Scanner(System.in);
//        serverCommands();
//        client = new Clients();
//        Clients sherif = new Clients("1236547896541596", "Sherif", "dh []uhk i, ]i hgfhs,v]".toCharArray(), "+201280412208");
        Clients sherif = new Clients("1236547896541596", "Sherif", "q2".toCharArray(), "+201280412208");
        Clients zezo = new Clients("45", "zezo", "a2".toCharArray(), "51");
        Clients zeco = new Clients("223344", "zeco", "ૻ22\u0CC933ྟ22ض33ዹ33".toCharArray(), "+2012");
        AddClient(sherif);
        AddClient(zezo);
        AddClient(zeco);
//        System.out.println(getClientsList());
//        for (Clients client : getClientsList()) {
//            if ((client.getClientID().toString()).equals("+201280412208")) {
//                System.out.println("Exist");
//                break;
//            } else {
//                System.out.println("UnKnown");
//            }
//        }

//        for (int i = 0; i < this.getClientsList().size(); i++) {
////            Clients clients = this.getClientsList().get(i).getClientID();
//            if ((this.getClientsList().get(i).getClientID().toString()).equals("+201280412208")) {
//                System.out.println("Exist");
//            } else {
//                System.out.println("UnKnown");
//            }
//        }



//        publicParameters = new publicParameters();
        BigInteger x = new BigInteger("425826231723888350446541592701409065913635568770");
        BigInteger y = new BigInteger("203520114162904107873991457957346892027982641970");
        ECPoint p = new ECPoint(x, y);

        BigInteger n = new BigInteger("1461501637330902918203687197606826779884643492439");

        BigInteger a = new BigInteger("1461501637330902918203684832716283019653785059324");

        BigInteger b = new BigInteger("163235791306168110546604919403271579530548345413");

        BigInteger q = new BigInteger("1461501637330902918203684832716283019653785059327");

        EllipticCurve curve = new EllipticCurve(a, b, q, p);

        publicParameters.setBasePoint(p);
        publicParameters.setCurve(curve);
        publicParameters.setOrder(n);
        process();
    }

    private void AddClient(Clients Clients) {
        clientsList.add(Clients);
    }

    private void process() {
        System.out.println(publicParameters.getCurve());
        while(publicParameters.getCurve() == null) {
            System.out.println("\nPlease insert the curve parameters");
            handleCurve(scanner);
            while(publicParameters.getBasePoint() == null) {
                System.out.println("\nPlease insert the BasePoint parameters");
                handleBasePoint(scanner);
                if(publicParameters.getBasePoint() != null) {
                    break;
                }
            }
            // break will take you here.
//        Running = true;
//            serverCommands();
//            System.out.println("Runnind is " + Running);
//                BankConnection connection = new BankConnection(8818, (parameters.publicParameters) publicParameters, Running);
//                connection.start();
//                try {
//                    serverSocket = new ServerSocket(serverPort);
//                    while (Running) {
//                        if (publicParameters.getBankID() != null || publicParameters.getBankPublicKey() != null) {
//                            System.out.println("*****************lolo*********************");
//                            System.out.println("About to accept client connection...");
//                            Socket clientSocket = serverSocket.accept();
//                            worker = new ServerWorker(this, clientSocket, (parameters.publicParameters) publicParameters);
//                            workerList.add(worker);
//                            worker.start();
//                        }
//                    }
//                } catch (IOException e) {
//                    System.out.println("\nError " + e.getMessage() + "\n");
//
//                }
        }
//        Running = true;
        serverKeyGeneration();
        serverCommands();
        System.out.println("Runnind is " + Running);

        while (Running ) {
            if (bankConnection == null && bankConnected == false) {
                bankConnection = new BankConnection(this, 8818, (parameters.publicParameters) publicParameters, Running);
                bankConnection.start();
                bankConnected = true;
//                clientConnection = null;
            }
            if (bankConnected == true) {
                ClientConnection();
            }

//            if(clientConnection != null && !bankConnected){
//                clientConnection.interrupt();
//                clientConnection = null;
//            }
//
//            if (publicParameters.getBankPublicKey() != null || clientConnection == null ) {
//                clientConnection = new ClientConnection(this, 7894, (parameters.publicParameters) publicParameters, Running);
//                clientConnection.start();
//            }
        }



//        while (Running) {
////            System.out.println(publicParameters.getBankAddress());
//            if (publicParameters.getBankAddress() == null ||
//                    publicParameters.getBankID() == null ||
//                    publicParameters.getBankPort() == 0 ||
//                    publicParameters.getBankPublicKey() == null){
////                acceptClients(false);
//                return;
//            }
//
//            System.out.println("Not Null");
//            acceptClients(true);
//        }
//        System.out.println("Break");
    }

    public void ClientConnection() {
//        while (Running) {
//            System.out.println(publicParameters.getBankAddress());
            if (publicParameters.getBankPublicKey() != null) {
                System.out.println("Not Null");
                try {
//                    serverSocket = new ServerSocket(serverPort);
                    if (serverSocket == null) {
                        serverSocket = new ServerSocket(7894);
                    }
                    while (Running) {
                        if (bankConnected == false){
//                            serverSocket.close();
//                            Close() ;
                            break;
                        }

                        if (publicParameters.getBankAddress() != null || publicParameters.getBankPublicKey() != null) {

                            Socket clientSocket = serverSocket.accept();
                            System.out.println("*****************lolo*********************");
                            System.out.println("About to accept client connection...");
                            worker = new ServerWorker(this, clientSocket, (parameters.publicParameters) publicParameters);
                            workerList.add(worker);
                            worker.start();
                        }
                    }
                } catch (IOException e) {
                    System.out.println("\nError " + e.getMessage() + "\n");
                }
//                break;
            }
//         }
    }

    private void Close() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
            if (worker != null) {
                worker.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private void serverKeyGeneration() {
        ECPoint P_KGC = new ECPoint();
        do {
            while (publicParameters.getBasePoint() == null) {
                handleBasePoint(scanner);
            }
            try {
//                do {
//                    d_KGC = Uty.randomBig(publicParameters.getOrder());
//                } while (d_KGC == null);
//                System.out.println("d_KGC " + d_KGC);
                d_KGC = new BigInteger("453631514880208263302514892664580839391019648211");
                System.out.println("d_KGC " + d_KGC);
                P_KGC = publicParameters.getCurve().multiply(publicParameters.getBasePoint(), d_KGC);

                publicParameters.setKgcPublic(P_KGC);
                System.out.println("P_KGC " + P_KGC);

                Running = true;
            } catch (Exception e) {
                System.out.println(e.getMessage());
                System.out.println(" Re Entre Curve Parameters ");
                handleCurve(scanner);
                Running = false;
            }
        } while (P_KGC.isPointOfInfinity() || publicParameters.getBasePoint() == P_KGC || P_KGC == new ECPoint(0, 0));
//        publicParameters.setKgcPublic(P_KGC);
    }

//    private void setPublicParameters() {
//        newParameters = new Thread("newParametersProcessing") {
//            public void run() {
//                if(bankConnection.connect()){
//                    bankConnection.send("public", publicParameters.getCurve());
//                    try {
//                        TimeUnit.SECONDS.sleep(2);
//                    } catch (InterruptedException e) {
//                        e.printStackTrace();
//                    }
//                    parametersToConnectedClients();
//                }
//                ;
//            }
//        };
//        newParameters.start();
//    }

//    private void setPublicParameters(){
//        if(bankConnection.connect()){
//            bankConnection.send("public", publicParameters.getCurve());
//            try {
//                TimeUnit.SECONDS.sleep(2);
//            } catch (InterruptedException e) {
//                e.printStackTrace();
//            }
//            parametersToConnectedClients();
//        }
//    }

    private void parametersToConnectedClients() {
        List<Clients> clientsList = this.getClientsList();
        for (Clients client : clientsList){
            clientConnection.getWorker().send("public", this.getClientsList());
        }
        newParameters.interrupt();
    }


    private void serverCommands() {
        Thread commands = new Thread("commands") {
            public void run() {
                System.out.println("\n************ Server Up & ready ************\n");
                commands();
            }
        };
        commands.start();
    }

    private void commands() {
        while (Running) {
            String text = scanner.nextLine();
            if (text.startsWith("/")) {
                text = text.substring(1);
                if (text.equalsIgnoreCase("workers")) {
                    System.out.println("workers:");
                    System.out.println("========");
                    for (int i = 0; i < clientConnection.getWorkerList().size(); i++) {
                        ServerWorker Work = clientConnection.getWorkerList().get(i);
                        System.out.println(Work.getAddress().toString() + ":" + Work.getPort());
                    }
                    System.out.println("========");
                } else if (text.equalsIgnoreCase("setCurve")){
                    System.out.println("Set Curve Parameters ");
                    handleCurve(scanner);
//                    setPublicParameters();
                    System.out.println("========");

                } else if (text.equalsIgnoreCase("add")){
                    System.out.println("Set Client Parameters ");
                    handleClientsAddition(scanner);
//                    setPublicParameters();
                    System.out.println("========");
                }  else if (text.equalsIgnoreCase("setPoint")){
                    System.out.println("Set BasePoint ");
                    handleBasePoint(scanner);
//                    setPublicParameters();
                    System.out.println("========");
                } else if (text.equalsIgnoreCase("clients")) {
                    System.out.println("parameters.Clients:");
                    System.out.println("========");
                    for (int i = 0; i < this.getClientsList().size(); i++) {
                        Clients clients = this.getClientsList().get(i);
                        System.out.println(clients.toString());
                        System.out.println("========");
                    }
                }else if (text.equalsIgnoreCase("help")) {
                    printHelp();
                } else if (text.equalsIgnoreCase("pars")) {
//                    publicParameters.printParameters();
                    System.out.println(publicParameters.toString());
                    System.out.println("========");
                } else if (text.equalsIgnoreCase("quit")) {
                        quit();
                } else {
                    System.out.println("Unknown command.");
                    printHelp();
                }
            }else{
                printHelp();
            }
        }
        scanner.close();
    }

    private void quit() {
        Running = false;
//        try {
//            serverSocket.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }finally {
//            System.exit(0);
//        }
        System.exit(0);
    }

    private void handleCurve(Scanner keyBoard) {

        do {
            System.out.println("Enter curve Co-officiant A ");
            BigInteger a = bigInteger(keyBoard);

            System.out.println("Enter curve Co-officiant B ");
            BigInteger b = bigInteger(keyBoard);

            System.out.println("Enter curve Field  ");
            BigInteger q = bigInteger(keyBoard);

            try {
                EllipticCurve curve = new EllipticCurve(a, b, q);
                publicParameters = new publicParameters();
                publicParameters.setCurve(curve);
                handleBasePoint(keyBoard);
                Running = true;
            } catch (Exception e) {
                System.out.println(e.getMessage());
                System.out.println("Re Enter Curve ");
                Running = false;
            }
        } while (!Running);
    }

    private void handleClientsAddition(Scanner keyBoard) {

            System.out.println("Enter client's account number ");
            BigInteger Number = bigInteger(keyBoard);
            String a = Number.toString();

            System.out.println("Enter UserName ");
            String b = keyBoard.next();

            System.out.println("Enter Password ");
            String c = keyBoard.next();

            System.out.println("Enter ClientID ");
            String d = keyBoard.next();

            Clients newClient = new Clients(a, b, c.toCharArray(), d);
            AddClient(newClient);
    }

    private void handleBasePoint(Scanner keyBoard) {

        ECPoint point = null;
        do {
            try {
                System.out.println("Enter BasePoint X_ coordination");
                BigInteger x = bigInteger(scanner);
                System.out.println("Enter BasePoint Y_ coordination ");
                BigInteger y = bigInteger(scanner);
                point = new ECPoint(x, y);
            } catch (Exception e) {
                System.out.println(e.getMessage());
                System.out.println("Re Enter BasePoint ");
            }
        } while (point.isPointOfInfinity() || point == null || point == new ECPoint(0, 0));
        publicParameters.setBasePoint(point);
        System.out.println("Enter Point Order ");
        BigInteger order = bigInteger(scanner);
        publicParameters.setOrder(order);
        serverKeyGeneration();
    }

    private BigInteger bigInteger(Scanner keyBoard) {
        BigInteger number;
            while (!keyBoard.hasNextBigInteger()) {
                System.out.println("Not BigInteger");
                keyBoard.next(); // this is important!
            }
            number = keyBoard.nextBigInteger();
        return number;
    }
    private Long getLong(Scanner keyBoard) {
        Long number;
            while (!keyBoard.hasNextLong()) {
                System.out.println("Not BigInteger");
                keyBoard.next(); // this is important!
            }
            number = keyBoard.nextLong();
        return number;
    }


    private void printHelp() {
        System.out.println("Here is a list of all available commands:");
        System.out.println("=========================================");
        System.out.println("/add - Add new Client.");
        System.out.println("/raw - enables raw mode.");
        System.out.println("/clients - shows all connected clients.");
        System.out.println("/kick [users ID or username] - kicks a user.");
        System.out.println("/help - shows this help message.");
        System.out.println("/quit - shuts down the server.");
    }

    public static BigInteger getPrivate() {
        return d_KGC;
    }


}
