import parameters.publicParameters;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class ClientConnection extends Thread{
    private final Server server;
    private final int serverPort;
    private final parameters.publicParameters publicParameters;
    private boolean serverStatus;
    private ServerSocket serverSocket;
    private ServerWorker worker;

    public ServerWorker getWorker() {
        return worker;
    }

    public ArrayList<ServerWorker> getWorkerList() {
        return workerList;
    }

    private static ArrayList<ServerWorker> workerList = new ArrayList<>();


    public ClientConnection(Server server, int serverPort, publicParameters publicParameters, boolean serverStatus) {
        this.server = server;
        this.serverPort = serverPort;
        this.publicParameters = publicParameters;
        this.serverStatus = serverStatus;
    }

    @Override
    public void run() {
        super.run();
        if (!serverStatus) {
            System.out.println("Server is not running");
            return;
        }
                try {
                    serverSocket = new ServerSocket(serverPort);
//                if (!(serverSocket.isBound()) )
//                    break;
                } catch (IOException e) {
                    e.printStackTrace();
                }



        while (serverStatus) {
//            System.out.println(publicParameters.getBankAddress());
//            if (publicParameters.getBankAddress() == null ||
//                    publicParameters.getBankID() == null ||
//                    publicParameters.getBankPort() == 0 ||
//                    publicParameters.getBankPublicKey() == null)
//                return;
//            {
//
//                System.out.println("Not Null");


                try {
                            System.out.println("*****************lolo*********************");
                            System.out.println("About to accept client connection...");
                            Socket clientSocket = serverSocket.accept();
                            worker = new ServerWorker(server, clientSocket, publicParameters);
                            workerList.add(worker);
                            worker.start();


                } catch (IOException e) {
                    System.out.println("\nError " + e.getMessage() + "\n");
                }
                break;
//            }
        }
    }

    private void Close() {
        try {
            serverSocket.close();
            worker.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public  void removeWorker(ServerWorker serverWorker) {
        workerList.remove(serverWorker);
    }

}

