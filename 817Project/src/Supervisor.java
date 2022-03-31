import java.io.IOException;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


public class Supervisor {

    public static void main(String[] args) throws IOException {

        Cipher supervisorCipher;
        PublicKey pk_A, pk_B;
        PrivateKey prK_B;
        KeyPair kP_B;
        KeyPairGenerator kPG_B;
        int Port = 10001;


        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~");
        System.out.println("| Supervisor Interface |");
        System.out.println("~~~~~~~~~~~~~~~~~~~~~~~~");
        ServerSocket sock = new ServerSocket(Port);
        System.out.println("Starting connection to Client's terminal on socket: " + Port);
        Socket SockClient = sock.accept();
        System.out.println("Successfully Connected to Client");
        Scanner inputClient = new Scanner(SockClient.getInputStream());
        PrintStream printStr = new PrintStream(SockClient.getOutputStream());

        try {

            kPG_B = KeyPairGenerator.getInstance("RSA");
            kP_B = kPG_B.generateKeyPair();
            pk_B = kP_B.getPublic();
            prK_B = kP_B.getPrivate();
            String pbkS_B = Base64.getEncoder().encodeToString(pk_B.getEncoded());
            printStr.println(pbkS_B);
            supervisorCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            supervisorCipher.init(Cipher.DECRYPT_MODE, prK_B);
            String ClientIdentifier = inputClient.nextLine();
            String nonceA_Client = inputClient.nextLine();
            byte[] c_BC = Base64.getDecoder().decode(ClientIdentifier);
            byte[] c_NonceBC = Base64.getDecoder().decode(nonceA_Client);
            ClientIdentifier = new String(supervisorCipher.doFinal(c_BC));
            nonceA_Client = new String(supervisorCipher.doFinal(c_NonceBC));
            System.out.println("Client's ID is: " + ClientIdentifier + " -- with timestamp: -- " + nonceA_Client );

            String SupervisorPubK_A = inputClient.nextLine();
            byte[] supervisor_nABC = Base64.getDecoder().decode(SupervisorPubK_A);
            X509EncodedKeySpec X509_KeySpec = new X509EncodedKeySpec(supervisor_nABC);
            pk_A = KeyFactory.getInstance("RSA").generatePublic(X509_KeySpec);
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String date_B = dateFormat.format(new Date());
            supervisorCipher.init(Cipher.ENCRYPT_MODE, pk_A);
            byte[] client_NonceABC2 = supervisorCipher.doFinal(nonceA_Client.getBytes("UTF-8"));
            byte[] client_NonceBBC2 = supervisorCipher.doFinal(date_B.getBytes("UTF-8"));
            String encrypted_nA = Base64.getEncoder().encodeToString(client_NonceABC2);
            String encrypted_nB = Base64.getEncoder().encodeToString(client_NonceBBC2);
            printStr.println(encrypted_nA);
            printStr.println(encrypted_nB);

            supervisorCipher.init(Cipher.DECRYPT_MODE, prK_B);
            String c_NonceB = inputClient.nextLine();
            byte[] c_BDecByteCode = Base64.getDecoder().decode(c_NonceB);
            c_NonceB = new String(supervisorCipher.doFinal(c_BDecByteCode));
            System.out.println("Received Timestamp: " + c_NonceB);

            String session_Key = inputClient.nextLine();
            String saltEncrypted = inputClient.nextLine();

            byte[] session_KeyByteCode = Base64.getDecoder().decode(session_Key);
            byte[] encrypted_saltByteCode = Base64.getDecoder().decode(saltEncrypted);
            String session_KeyByteDecode = new String(supervisorCipher.doFinal(session_KeyByteCode));
            String saltString = new String(supervisorCipher.doFinal(encrypted_saltByteCode));


            IvParameterSpec ivPS = new IvParameterSpec(new byte[16]);
            System.out.println("Session Key: " + session_KeyByteDecode);
            System.out.println("Salt: " + saltString);
            System.out.println("iv: " + ivPS);

            String encrypted_cardHolderName = inputClient.nextLine();
            System.out.println("Encrypted Cardholder Name: " + encrypted_cardHolderName);

            String encrypted_cardNumber = inputClient.nextLine();
            System.out.println("Encrypted Credit Card Number: " + encrypted_cardNumber);

            String encrypted_cardExp = inputClient.nextLine();
            System.out.println("Encrypted Credit Card Expiry: " + encrypted_cardExp);

            String encrypted_cardCVV = inputClient.nextLine();
            System.out.println("Encrypted Credit Card CVV Code: " + encrypted_cardCVV);

            String encrypted_PostalCode = inputClient.nextLine();
            System.out.println("Encrypted Client postal Code: " + encrypted_PostalCode);

            String encrypted_itemOrdered = inputClient.nextLine();
            System.out.println("Encrypted item purchased: " + encrypted_itemOrdered);

            SecretKey SecretKey_Gen = Utility.genKeyWithSalt(session_KeyByteDecode, saltString);

            String decrypted_Name = Utility.decrypt(encrypted_cardHolderName, SecretKey_Gen, ivPS);
            String decrypted_Number = Utility.decrypt(encrypted_cardNumber, SecretKey_Gen, ivPS);
            String decrypted_Exp = Utility.decrypt(encrypted_cardExp, SecretKey_Gen, ivPS);
            String decrypted_CVV = Utility.decrypt(encrypted_cardCVV, SecretKey_Gen, ivPS);
            String decrypted_PostalCode = Utility.decrypt(encrypted_PostalCode, SecretKey_Gen, ivPS);
            String decrypted_itemOrdered = Utility.decrypt(encrypted_itemOrdered, SecretKey_Gen, ivPS);

            System.out.println("Decrypted Cardholder Name: " + decrypted_Name);
            System.out.println("Decrypted Credit Card Number: " + decrypted_Number);
            System.out.println("Decrypted Expiry Date in MMYY: " + decrypted_Exp);
            System.out.println("Decrypted Credit Card CVV Code: " + decrypted_CVV);
            System.out.println("Decrypted Postal Code: " + decrypted_PostalCode);
            System.out.println("Decrypted Item Ordered: " + decrypted_itemOrdered);


        }
        catch (IOException i) {
            System.out.println(i);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

}
