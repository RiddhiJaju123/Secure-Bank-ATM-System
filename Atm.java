import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.X509EncodedKeySpec;

public class Atm {
    private Socket socket = null;
    private DataOutputStream out = null;
    private DataInputStream in = null;
    private BufferedReader input = null;

    public Atm(String address, int port) {
        SecretKey symmetricKey;
        String action_account;
        try {
            socket = new Socket(address, port);
            // System.out.println("Connected");
            input = new BufferedReader(new InputStreamReader(System.in));
            in = new DataInputStream(
                    new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(socket.getOutputStream());

            try {

                BufferedReader publicKeyReader = new BufferedReader(new FileReader("public_key.pem"));
                StringBuilder publicKeyPEM = new StringBuilder();
                String line;
                while ((line = publicKeyReader.readLine()) != null) {
                    if (!line.contains("-----BEGIN PUBLIC KEY-----") && !line.contains("-----END PUBLIC KEY-----")) {
                        publicKeyPEM.append(line);
                    }
                }
                publicKeyReader.close();

                byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM.toString());
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey bankPublicKey = keyFactory.generatePublic(publicKeySpec);

                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(256);
                symmetricKey = keyGenerator.generateKey();

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, bankPublicKey);
                String encryptedString = Base64.getEncoder().encodeToString(cipher.doFinal(symmetricKey.getEncoded()));
                out.writeUTF(encryptedString);

                while (true) {
                    Cipher symmetricCipher = Cipher.getInstance("AES");
                    symmetricCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                    System.out.print("Enter Your Id : ");
                    String userId = input.readLine();
                    byte[] encryptedUserData = symmetricCipher.doFinal((userId).getBytes());

                    String cipherTextStrId = Base64.getEncoder().encodeToString(encryptedUserData);
                    out.writeUTF(cipherTextStrId);

                    symmetricCipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
                    System.out.print("Enter Your password : ");
                    String password = input.readLine();
                    byte[] encryptedUserData1 = symmetricCipher.doFinal((password).getBytes());

                    String cipherTextStrPasswd = Base64.getEncoder().encodeToString(encryptedUserData1);
                    out.writeUTF(cipherTextStrPasswd);
                    if (in.readUTF().equals("ID and password are correct")) {
                        System.out.println("ID and password are correct");
                        break;
                    } else {
                        System.out.println("ID or password is incorrect");
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            while (true) {

                System.out.println(
                        "\nPlease select one of the following actions (enter 1, 2, or 3):\n1. Transfer money\n2. Check account balance\n3. Exit");
                System.out.println("\nPlease select one : ");
                String action = input.readLine();
                if (action.equals("3"))
                    break;
                else if (action.equals("1")) {

                    while (true) {
                        System.out.println("\nPlease select an account (enter 1 or 2): \n1. Savings\n2. Checkings");
                        System.out.println("\nPlease select one : ");
                        action_account = input.readLine();
                        if (action_account.equals("1") || action_account.equals("2")) {
                            break;
                        } else {
                            System.out.println("Incorrect Input.");
                        }
                    }

                    if (action_account.equals("1")) {
                        out.writeUTF("11");
                        System.out.println("Enter the ID of the recepient : ");
                        String userIdForTransfer = input.readLine();
                        out.writeUTF(userIdForTransfer);
                        System.out.println("Enter the amount to transfer money : ");
                        String amountForTransfer = input.readLine();
                        out.writeUTF(amountForTransfer);
                        String message = in.readUTF();

                        if (message.equals("the recipient’s ID does not exist")) {
                            System.out.println("the recipient’s ID does not exist");
                            continue;
                        }

                        String status = in.readUTF();
                        if (status.equals("Your account does not have enough funds")) {
                            System.out.println("Your account does not have enough funds");
                        } else {
                            System.out.println("your transaction is successful");
                        }
                    } else if (action_account.equals("2")) {

                        out.writeUTF("12");
                        System.out.println("Enter the ID of the recepient : ");
                        String userIdForTransfer = input.readLine();
                        out.writeUTF(userIdForTransfer);
                        System.out.println("Enter the amount to transfer money : ");
                        String amountForTransfer = input.readLine();
                        out.writeUTF(amountForTransfer);
                        String message = in.readUTF();

                        if (message.equals("the recipient’s ID does not exist")) {
                            System.out.println("the recipient’s ID does not exist");
                            continue;
                        }
                        String status = in.readUTF();
                        if (status.equals("Your account does not have enough funds")) {
                            System.out.println("Your account does not have enough funds");

                        } else {
                            System.out.println("your transaction is successful");
                        }
                    } else {
                        System.out.println("Incorrect Input");
                    }

                } else if (action.equals("2")) {
                    out.writeUTF("2");
                    String ba1 = in.readUTF();
                    String ba2 = in.readUTF();
                    System.out.println("Your savings account balance:" + ba1);
                    System.out.println("Your checkings account balance:" + ba2);
                } else {
                    System.out.println("incorrect input");
                }
            }

        } catch (UnknownHostException u) {
            System.out.println(u);
        } catch (IOException i) {
            System.out.println(i);
        } catch (Exception e) {
            System.out.println(e);
        }

        try {
            System.out.println("Exiting and closing the client.");
            if (input != null)
                input.close();
            if (out != null)
                out.close();
            if (socket != null)
                socket.close();
        } catch (IOException i) {
            System.out.println(i);
        }
    }

    public static void main(String args[])
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        try {

            if (args.length != 2) {
                System.out.println("Usage: java ATMClient <Bank server's domain name> <Bank server's port number>");
                System.exit(1);
            }
            String serverName = args[0];
            int serverPort = Integer.valueOf(args[1]);

            String iaddress = InetAddress.getByName(serverName).getHostAddress();

            Atm cli = new Atm(iaddress, serverPort);

        } catch (UnknownHostException e) {
            System.out.println(e);
        }

        catch (Exception e) {
            System.out.println(e);
        }

    }
}