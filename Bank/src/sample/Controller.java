package sample;

import Util.Uty;
import algorithm.Algorithm;
//import com.google.gson.Gson;
//import com.sun.jmx.snmp.tasks.Task;
import algorithm.Steganograpgy.HelperMethods;
import connection.BankServer;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import parameters.Bank;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;


public class Controller  implements Initializable{

    @FXML
    private TextField txtAcc ;
    @FXML
    private Button btnsm ;
    @FXML
    private CheckBox chs;
    @FXML
    private Button btnsi ;
    @FXML
    private Button btnso ;
    @FXML
    private Button  btnse;
    @FXML
    private Button btnsc ;
    @FXML
    private Button  btnrm;
    @FXML
    private Button btnro ;
    @FXML
    private Button  btnre;
    @FXML
    private Button  btnrc;
    @FXML
    private ListView listview;
    @FXML
    String fileAsString;
    @FXML
    String stegFileAsString;
    @FXML
    String outputFile;
    @FXML
    String outputDir;
    @FXML
    String[] srcFiles;
    @FXML
    ArrayList<String> filesAsString;
    @FXML
    File selectedFile;
    @FXML
    File stegFile;
    @FXML
    File saveFile;
    @FXML
    File selectedDirectory;
    @FXML
    List<File> selectedFiles;
    @FXML
    private ArrayList<Button> buttonArrayList;
    @FXML
    private Algorithm algorithm;
    @FXML
    private HashMap<String, Object> newMap;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        buttonsList();
        Thread thread = new Thread();
        final Thread finalThread = thread;
        thread = new Thread("getBankPublicKey") {
            public void run() {
                disableButtons();
                BankServer bankClient = new BankServer();
                while (Bank.getPublicKey() == null) {
                    bankClient = new BankServer("localhost", 8818);
//                    bankClient = new BankServer("192.168.1.135", 8818);
                    bankClient.start();
                    bankClient.interrupt();
                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    System.out.println("Interrupted");
                    if(Bank.getPublicKey() != null) {
                        System.out.println("Connected");
                        algorithm = new Algorithm(bankClient);
                        enableButtons();
                        finalThread.interrupt();
                        break;
                    }
                }
            }
        };
        thread.start();

    }


    public void checkBox(){
        btnsi.disableProperty().bind(chs.selectedProperty().not());
    }


    public void singleChooser(){
        FileChooser fc = new FileChooser();

        fc.setInitialDirectory(new File("C:\\"));

        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Files",  "*.png", "*.txt"));

        selectedFile = fc.showOpenDialog(null);
        if(selectedFile != null){
//            listview.getItems().add(selectedFile);
            fileAsString = selectedFile.toString();
        }
    }

    public void steg(){
        FileChooser fc = new FileChooser();
//        fc.setInitialDirectory(new File(System.getProperty("D:\\")));
        fc.setInitialDirectory(new File("C:\\"));
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter
                ("Image Files", "*.png", "*.jpg", "*.jpeg"));

        stegFile = fc.showOpenDialog(null);
        if(stegFile != null){
//            listview.getItems().add(selectedFile);
            stegFileAsString = stegFile.toString();
        }
    }


    public void multiChooser() {
        FileChooser fc = new FileChooser();
        fc.setInitialDirectory(new File("C:\\"));
        selectedFiles = fc.showOpenMultipleDialog(null);
//        Object[] files = new Object[0];
        String files = null;
        filesAsString = new ArrayList<>();
        if (selectedFiles != null) {
            for(File s : selectedFiles)
                filesAsString.add(s.toString());
            srcFiles = filesAsString.toArray(new String[filesAsString.size()]);
//            listview.getItems().addAll(selectedFile);
//            files = selectedFile.toArray();

//            filesAsString = Arrays.toString(files).split(",");
        }
//        filesAsString = Arrays.copyOf(files, files.length, String[].class);
    }

    public void fileSaving(){
        FileChooser fc = new FileChooser();
//        fc.setInitialDirectory(new File(System.getProperty("D:\\")));
        fc.setInitialDirectory(new File("C:\\"));

        if (chs.isSelected()) {
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("PNG Files", "*.png"));
        }
        else
            fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT Files", "*.txt"));

        saveFile = fc.showSaveDialog(null);
        if (saveFile != null) {
            outputFile = saveFile.toString();
        }
        else outputFile = null;

    }

    public void outputDir(){
        DirectoryChooser dc = new DirectoryChooser();
//        chooser.setTitle("JavaFX Projects");
        File defaultDirectory = new File("C:\\");
        dc.setInitialDirectory(defaultDirectory);
        selectedDirectory = dc.showDialog(null);
        if (selectedDirectory != null) {
            outputDir = selectedDirectory.toString();
        }
        else outputDir = null;
    }



    public void senderExecute(){
        if (txtAcc.getText() == "") {
            System.out.println("Please Enter Client AccountNumber");
            return;
        }
        if (selectedFiles == null) {
            System.out.println("Please select secret message");
            return;
        }
        if (saveFile == null) {
            System.out.println("select output file");
            return;
        }
        if (chs.isSelected() && stegFile == null) {
            System.out.println("select carrier image");
            return;
        }
        if (txtAcc.getText() == "") {
            System.out.println("Account number is null");
            return;
        }
        new Thread() {
            public void run() {
                Platform.runLater(new Runnable() {
                    public void run() {
                        disableButtons();
                    }
                });
                SendProcess();
                Platform.runLater(new Runnable() {
                    public void run() {
                        enableButtons();
                    }
                });
            }
        }.start();

    }

    private void SendProcess() {
        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("BSCrypto");
            HashMap<String, Object> hmap = algorithm.signcryption(srcFiles, tempDir, txtAcc.getText());
            if (hmap == null) {
                System.out.println("hashmap is null");
                return;
            }
            if (!(chs.isSelected())) {
                Uty.WriteMapToFile(hmap, saveFile);
            } else {
                String serialized = Uty.serialize(hmap);
//                algorithm.embed(serialized, stegFileAsString, outputFile);
                algorithm.embed(serialized, stegFile, saveFile);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if (tempDir != null) {
                Uty.remove(tempDir);
            }
            txtAcc.setText("");
            srcFiles = null;
            stegFileAsString = "";
            outputFile = "";
        }

    }


    public void receiveExecute(){
        if(selectedFile == null){
            System.out.println("please select a file");
            return;
        }
        if(selectedDirectory == null){
            System.out.println("please select am output directory");
            return;
        }

        new Thread() {
            public void run() {
                Platform.runLater(new Runnable() {
                    public void run() {
                        disableButtons();
                    }
                });

                ReceiveProcess();

                Platform.runLater(new Runnable() {
                    public void run() {
                        enableButtons();

                    }
                });
            }
        }.start();

    }

    private void ReceiveProcess() {
        if (fileAsString.endsWith(".png") == true) {

            String message = algorithm.extract(fileAsString);
            System.out.println("ddddddddddddddddddddddddddddddddddddsdsde");
            String bits = (String) message;
            byte[] messageBytes = HelperMethods.bitsStreamToByteArray(bits);
            String serialized = new String(messageBytes);
            System.out.println(serialized);
            try {
                newMap = (HashMap<String, Object>) Uty.deserialize(serialized);
            } catch (IOException e) {
                e.printStackTrace();
            }

        } else {
            newMap = Uty.fileToMap(fileAsString);
        }

        Path tempDir_received = null;
        String deOutput = null;
        try {
            tempDir_received = Files.createTempDirectory("BRCrypto");
            deOutput = tempDir_received + "/plain.zip";
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte[] plainText = null;
        try {
            plainText = algorithm.unSigncryption(newMap);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (plainText != null) {
            Uty.writeByteToFile(tempDir_received + "/plain.zip", plainText);
            Uty.unZipIt(deOutput, outputDir);
        } else {
            System.out.println(" Empty Message");
        }

        Uty.remove(tempDir_received);
    }

    private void buttonsList() {
        buttonArrayList =new ArrayList<>();
        buttonArrayList.add(btnsm);
//        buttonArrayList.add(btnsi);
        buttonArrayList.add(btnso);
        buttonArrayList.add(btnse);
        buttonArrayList.add(btnsc);
        buttonArrayList.add(btnrm);
        buttonArrayList.add(btnro);
        buttonArrayList.add(btnre);
        buttonArrayList.add(btnrc);
    }

    public  void disableButtons() {

        for (Button btn : buttonArrayList) {
            btn.setDisable(true);
        }
        chs.setDisable(true);
//        chs.setSelected(false);
        txtAcc.setDisable(true);
//        btnsi.setDisable(true);

    }

    public void enableButtons() {
        for (Button btn : buttonArrayList) {
            btn.setDisable(false);
        }
        txtAcc.setDisable(false);
        chs.setDisable(false);
        chs.setSelected(false);
    }

}



