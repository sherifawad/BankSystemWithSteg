package connection;

import java.io.Serializable;

public class Message implements Serializable{
    private static final long serialVersionUID = 539317896475L;
    private  String command;
    private  String clientID;
    private  Object publicKey;
    private  Object messageBody;

    public Message() {
    }

    public Object getPublicKey() { return publicKey; }

    public String getCommand() {
        return command;
    }

    public String getClientID() {
        return clientID;
    }

    public Object getMessageBody() {
        return messageBody;
    }

    @Override
    public String toString() {
        return "connection.Message{" + "command='" + command + '\'' + ", clientID='" + clientID + '\'' + ", publicKey=" + publicKey + ", messageBody=" + messageBody + '}';
    }

    public Message(String command, String clientID, Object publicKey, Object messageBody) {
        this.command = command;
        this.clientID = clientID;
        this.messageBody = messageBody;
        this.publicKey = publicKey;
    }

}
