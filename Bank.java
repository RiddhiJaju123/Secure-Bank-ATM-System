import java.net.*;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.*;

class Bank {
    String number1;
    String number2;
    String name;
    String name_recipient;
    int flag = 0;
    StringBuilder privateKeyPEM;
    private Socket socket = null;
    private ServerSocket server = null;
    private DataInputStream in = null;
    private DataOutputStream out = null;

    public Bank(int port) {
        try {
            server = new ServerSocket(port);
            //System.out.println("Server started");
            //System.out.println("Waiting for a client");

            while (true) {
                try {

                    socket = server.accept();
                    //System.out.println("Client accepted");

                    in = new DataInputStream(
                            new BufferedInputStream(socket.getInputStream()));

                    out = new DataOutputStream(socket.getOutputStream());
                    String line = "";
                    String userId = "";

                    BufferedReader privateKeyReader = new BufferedReader(new FileReader("private_key.pem"));
                    privateKeyPEM = new StringBuilder();
                    String line1;
                    while ((line1 = privateKeyReader.readLine()) != null) {
                        if (!line1.contains("-----BEGIN PRIVATE KEY-----")
                                && !line1.contains("-----END PRIVATE KEY-----")) {
                            privateKeyPEM.append(line1);
                        }
                    }
                    privateKeyReader.close();

                    byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM.toString());
                    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PrivateKey bankPrivateKey = keyFactory.generatePrivate(privateKeySpec);

                    String encryptedString = (String) in.readUTF();
                    byte[] encryptedStringbyte = Base64.getDecoder().decode(encryptedString);
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.DECRYPT_MODE, bankPrivateKey);
                    byte[] receivedEncryptedSymmetricKey = encryptedStringbyte;
                    byte[] symmetricKeyBytes = cipher.doFinal(receivedEncryptedSymmetricKey);
                    SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");

                    while (true) {

                        try {

                            String cipherTextStrUserId = in.readUTF();

                            byte[] cipherTextId = Base64.getDecoder().decode(cipherTextStrUserId);
                            Cipher symmetricCipher = Cipher.getInstance("AES");
                            symmetricCipher.init(Cipher.DECRYPT_MODE, symmetricKey);
                            byte[] receivedEncryptedUserData = cipherTextId;
                            byte[] userDataBytes = symmetricCipher.doFinal(receivedEncryptedUserData);
                            userId = new String(userDataBytes);

                            String cipherTextStrPasswd = (String) in.readUTF();

                            byte[] cipherTextPasswd = Base64.getDecoder().decode(cipherTextStrPasswd);
                            Cipher symmetricCipher1 = Cipher.getInstance("AES");
                            symmetricCipher1.init(Cipher.DECRYPT_MODE, symmetricKey);
                            byte[] receivedEncryptedUserData1 = cipherTextPasswd;
                            byte[] userDataBytes1 = symmetricCipher.doFinal(receivedEncryptedUserData1);
                            String password = new String(userDataBytes1);

                            File passObj = new File(System.getProperty("user.dir") + "/password.txt");
                            FileReader fr = new FileReader(passObj);
                            BufferedReader br = new BufferedReader(fr);
                            boolean found = false;
                            while ((line = br.readLine()) != null) {

                                if (line.substring(0, userId.length()).equals(userId) &&
                                        line.substring(userId.length() + 1, line.length()).equals(password)) {
                                    found = true;
                                    //System.out.println("ID and password are correct");
                                    out.writeUTF("ID and password are correct");

                                    break;
                                }

                            }

                            br.close();
                            fr.close();

                            if (!found) {
                                out.writeUTF("ID or password is incorrect");
                                //System.out.println("ID or password is incorrect");
                                continue;
                            } else
                                break;
                        }

                        catch (IOException i) {

                            //System.out.println("Client connection closed. Waiting for new connection.");
                            break;
                        } catch (Exception e) {
                            System.out.println(e);
                        }
                    }

                    while (true) {
                        File balObj = new File(System.getProperty("user.dir") + "/balance.txt");
                        FileReader balFR = new FileReader(balObj);
                        BufferedReader balBR = new BufferedReader(balFR);

                        while ((line = balBR.readLine()) != null) {

                            String[] words = line.split(" ");

                            if (words.length >= 3) {
                                name = words[0];

                                if (name.equals(userId)) {

                                    number1 = words[1];
                                    number2 = words[2];
                                    name = words[0];

                                    break;
                                }
                            }

                        }

                        balBR.close();
                        balFR.close();
                        String readonce = in.readUTF();
                        if (readonce.equals("11")) {

                            String userIdForTransfer = (String) in.readUTF();
                            String amountForTransfer = in.readUTF();
                            int amt = Integer.valueOf(amountForTransfer);
                            int bal = Integer.valueOf(number1);

                            File balObj1 = new File(System.getProperty("user.dir") + "/password.txt");
                            FileReader balFR1 = new FileReader(balObj1);
                            BufferedReader balBR1 = new BufferedReader(balFR1);

                            while ((line = balBR1.readLine()) != null) {

                                String[] words = line.split(" ");

                                if (words.length >= 2) {
                                    name_recipient = words[0];

                                    if (name_recipient.equals(userIdForTransfer)) {
                                        flag = 1;

                                    }
                                }

                            }

                            balBR1.close();
                            balFR1.close();
                            if (flag == 0) {
                                out.writeUTF("the recipient’s ID does not exist");
                                continue;
                            } else {
                                flag=0;
                                out.writeUTF("102");


                            }

                            if (amt > bal) {
                                out.writeUTF("Your account does not have enough funds");
                                continue;

                            }

                            else {

                                List<String> lines = new ArrayList<>();
                                BufferedReader br = new BufferedReader(
                                        new FileReader(System.getProperty("user.dir") + "/balance.txt"));
                                String line10;
                                while ((line10 = br.readLine()) != null) {
                                    lines.add(line10);
                                }
                                br.close();

                                for (int i = 0; i < lines.size(); i++) {
                                    String[] parts = lines.get(i).split(" ");
                                    if (parts.length >= 3 && parts[0].equals(name)) {
                                        int currentBalance = Integer.parseInt(parts[1]);
                                        int updatedBalance = currentBalance - amt;
                                        parts[1] = String.valueOf(updatedBalance);
                                        lines.set(i, String.join(" ", parts));
                                        break;
                                    }
                                }

                                BufferedWriter bw = new BufferedWriter(
                                        new FileWriter(System.getProperty("user.dir") + "/balance.txt"));
                                for (String updatedLine : lines) {
                                    bw.write(updatedLine);
                                    bw.newLine();
                                }
                                bw.close();

                                List<String> lines1 = new ArrayList<>();
                                BufferedReader br1 = new BufferedReader(
                                        new FileReader(System.getProperty("user.dir") + "/balance.txt"));
                                String line11;
                                while ((line11 = br1.readLine()) != null) {
                                    lines1.add(line11);
                                }
                                br1.close();

                                for (int i = 0; i < lines1.size(); i++) {
                                    String[] parts1 = lines1.get(i).split(" ");
                                    if (parts1.length >= 3 && parts1[0].equals(userIdForTransfer)) {
                                        int currentBalance = Integer.parseInt(parts1[1]);
                                        int updatedBalance = currentBalance + amt;
                                        parts1[1] = String.valueOf(updatedBalance);
                                        lines1.set(i, String.join(" ", parts1));
                                        break;
                                    }
                                }

                                BufferedWriter bw1 = new BufferedWriter(
                                        new FileWriter(System.getProperty("user.dir") + "/balance.txt"));
                                for (String updatedLine1 : lines1) {
                                    bw1.write(updatedLine1);
                                    bw1.newLine();
                                }
                                bw1.close();

                                //System.out.println("Balance updated successfully.");
                                out.writeUTF("your transaction is successful");

                            }

                        } else if (readonce.equals("12")) {

                            String userIdForTransfer = (String) in.readUTF();
                            String amountForTransfer = in.readUTF();
                            int amt = Integer.valueOf(amountForTransfer);
                            int bal = Integer.valueOf(number2);
                            /*System.out.println("JUST CROSSCHECKING");
                            System.out.println("Name: " + name);
                            System.out.println("Number 1: " + number1);
                            System.out.println("Number 2: " + number2);*/
                            File balObj2 = new File(System.getProperty("user.dir") + "/password.txt");
                            FileReader balFR2 = new FileReader(balObj2);
                            BufferedReader balBR2 = new BufferedReader(balFR2);

                            while ((line = balBR2.readLine()) != null) {

                                String[] words = line.split(" ");

                                if (words.length >= 2) {
                                    name_recipient = words[0];

                                    if (name_recipient.equals(userIdForTransfer)) {
                                        flag = 1;

                                    }
                                }

                            }

                            balBR2.close();
                            balFR2.close();
                            if (flag == 0) {
                                out.writeUTF("the recipient’s ID does not exist");
                                continue;
                            } else {
                                flag=0;
                                out.writeUTF("102");

                            }
                            if (amt > bal) {
                                out.writeUTF("Your account does not have enough funds");
                                continue;

                            } else {

                                List<String> lines = new ArrayList<>();
                                BufferedReader br = new BufferedReader(
                                        new FileReader(System.getProperty("user.dir") + "/balance.txt"));
                                String line10;
                                while ((line10 = br.readLine()) != null) {
                                    lines.add(line10);
                                }
                                br.close();

                                for (int i = 0; i < lines.size(); i++) {
                                    String[] parts = lines.get(i).split(" ");
                                    if (parts.length >= 3 && parts[0].equals(name)) {
                                        int currentBalance = Integer.parseInt(parts[2]);
                                        int updatedBalance = currentBalance - amt;
                                        parts[2] = String.valueOf(updatedBalance);
                                        lines.set(i, String.join(" ", parts));
                                        break;
                                    }
                                }

                                BufferedWriter bw = new BufferedWriter(
                                        new FileWriter(System.getProperty("user.dir") + "/balance.txt"));
                                for (String updatedLine : lines) {
                                    bw.write(updatedLine);
                                    bw.newLine();
                                }
                                bw.close();

                                List<String> lines1 = new ArrayList<>();
                                BufferedReader br1 = new BufferedReader(
                                        new FileReader(System.getProperty("user.dir") + "/balance.txt"));
                                String line11;
                                while ((line11 = br1.readLine()) != null) {
                                    lines1.add(line11);
                                }
                                br1.close();

                                for (int i = 0; i < lines1.size(); i++) {
                                    String[] parts1 = lines1.get(i).split(" ");
                                    if (parts1.length >= 3 && parts1[0].equals(userIdForTransfer)) {
                                        int currentBalance = Integer.parseInt(parts1[2]);
                                        int updatedBalance = currentBalance + amt;
                                        parts1[2] = String.valueOf(updatedBalance);
                                        lines1.set(i, String.join(" ", parts1));
                                        break;
                                    }
                                }

                                BufferedWriter bw1 = new BufferedWriter(
                                        new FileWriter(System.getProperty("user.dir") + "/balance.txt"));
                                for (String updatedLine1 : lines1) {
                                    bw1.write(updatedLine1);
                                    bw1.newLine();
                                }
                                bw1.close();

                                //System.out.println("Balance updated successfully.");
                                out.writeUTF("your transaction is successful");

                            }
                        } else if (readonce.equals("2")) {
                            out.writeUTF(number1);
                            out.writeUTF(number2);
                        } else {
                            break;
                        }
                    }

                    if (in != null) {
                        in.close();

                    }
                    if (out != null) {

                        out.close();
                    }
                    if (socket != null) {

                        socket.close();
                    }
                } catch (IOException i) {

                    continue;

                } catch (Exception e) {
                    System.out.println(e);
                }
            }
        } catch (IOException i) {

            System.out.println(i);
        } catch (Exception e) {
            System.out.println(e);
        }

    }

    public static void main(String args[]) throws NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, NoSuchPaddingException, BadPaddingException {

        if (args.length != 1) {
            System.out.println("Usage: java BankServer <Bank server's port number>");
            System.exit(1);
        }
        int port = Integer.valueOf(args[0]);
        try {

            Bank serv = new Bank(port);

        } catch (Exception e) {
            System.out.println(e);
        }
    }

}