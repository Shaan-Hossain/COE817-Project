
import java.beans.Encoder;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
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
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;
import java.text.SimpleDateFormat;
import java.math.*;

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


public class Client {

    public static void main(String[] args) throws IOException {

        Cipher clientCipher;
        PublicKey pk_A, pk_B;
        PrivateKey prK_A;
        KeyPair kP_A;
        KeyPairGenerator kPG_A;
        int Socket_Port = 10001;
        String initA = "Initiator A";
        String sessionKey;

        System.out.println("~~~~~~~~~~~~~~~~~~~~");
        System.out.println("| Client Interface |");
        System.out.println("~~~~~~~~~~~~~~~~~~~~");

        Socket sock = new Socket("localhost", Socket_Port);
        Scanner serverInput = new Scanner(sock.getInputStream());
        Scanner userInput = new Scanner(System.in);
        System.out.println("Connected to Supervisor");
        PrintStream printStr = new PrintStream(sock.getOutputStream());

        try{
            kPG_A = KeyPairGenerator.getInstance("RSA");
            kP_A = kPG_A.generateKeyPair();
            pk_A = kP_A.getPublic();
            prK_A = kP_A.getPrivate();
            String pkString_B = serverInput.nextLine();
            byte [] k_ByteB = Base64.getDecoder().decode(pkString_B);
            X509EncodedKeySpec X509_K_S = new X509EncodedKeySpec(k_ByteB);
            pk_B = KeyFactory.getInstance("RSA").generatePublic(X509_K_S);
            clientCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            clientCipher.init(Cipher.ENCRYPT_MODE,pk_B);

            SimpleDateFormat dF2 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String A_Date = dF2.format(new Date());
            byte[] client_iDAByteCode = clientCipher.doFinal(initA.getBytes("UTF-8"));
            byte[] client_NAByteCode = clientCipher.doFinal(A_Date.getBytes("UTF-8"));

            String encrypted_IDa = Base64.getEncoder().encodeToString(client_iDAByteCode);
            String encrypted_nA = Base64.getEncoder().encodeToString(client_NAByteCode);
            printStr.println(encrypted_IDa);
            printStr.println(encrypted_nA);
            String pb_A = Base64.getEncoder().encodeToString(pk_A.getEncoded());
            printStr.println(pb_A);
            String nonceA = serverInput.nextLine();
            String nonceB = serverInput.nextLine();
            clientCipher.init(Cipher.DECRYPT_MODE, prK_A);
            byte[] nonceA_ByteCode = Base64.getDecoder().decode(nonceA);
            byte[] nonceB_ByteCode = Base64.getDecoder().decode(nonceB);
            nonceA = new String(clientCipher.doFinal(nonceA_ByteCode));
            nonceB = new String(clientCipher.doFinal(nonceB_ByteCode));

            clientCipher.init(Cipher.ENCRYPT_MODE, pk_B);
            nonceB_ByteCode = clientCipher.doFinal(nonceB.getBytes("UTF-8"));
            String nonceB_Encrypted = Base64.getEncoder().encodeToString(nonceB_ByteCode);
            printStr.println(nonceB_Encrypted);

            SecureRandom random = new SecureRandom();
            byte bytes[] = new byte[20];
            random.nextBytes(bytes);
            sessionKey = Base64.getEncoder().encodeToString(bytes);

            IvParameterSpec ivPS = new IvParameterSpec(new byte[16]);
            String iv = ivPS.toString();

            byte[] salt = new byte[10];
            random.nextBytes(salt);
            String saltString = Base64.getEncoder().encodeToString(salt);

            char[] charSessionKey = new char[sessionKey.length()];
            System.out.println("Session Key: "+ sessionKey);
            System.out.println("Salt: "+ saltString);
            System.out.println("iv: "+ ivPS);

            byte[] ivByte = clientCipher.doFinal(iv.getBytes("UTF-8"));
            byte[] SessionKey_BC = clientCipher.doFinal(sessionKey.getBytes("UTF-8"));
            byte[] saltBC = clientCipher.doFinal(saltString.getBytes("UTF-8"));
            String encryted_SessionKeyBC = Base64.getEncoder().encodeToString(SessionKey_BC);
            String encryted_saltBC = Base64.getEncoder().encodeToString(saltBC);
            String encryted_ivBC = Base64.getEncoder().encodeToString(ivByte);

            printStr.println(encryted_SessionKeyBC);
            printStr.println(encryted_saltBC);
            printStr.println(encryted_ivBC);

            boolean ordering = true;
            String itemOrdered = "";

            while (ordering) {
                System.out.println("Which item would you like to purchase?");
                System.out.println("1. Prebuilt PC, price of: " + Math.random()*1000);
                System.out.println("2. NVIDIA 2080TI price of: " + Math.random()*1000);
                System.out.println("3. Intel i9 9990K price of: " + Math.random()*1000);
                System.out.println("4. Corsair Gold PSU price of: " + Math.random()*100);
                System.out.println("5. Quit");
                System.out.println("Please enter the number associated with the item, or 5 to quit: \n");
                String userChoice = userInput.nextLine();

                switch (userChoice) {
                    case "5" : ordering = false;
                    case "1" : {
                        itemOrdered = "Prebuilt PC";
                        System.out.println("Checking if the item is in stock.");
                        if (Math.random() * 10 > 3) {
                            System.out.println("This item is in stock, please proceed to checkout.");
                            ordering = false;
                            }
                        else
                            System.out.println("This item is not in stock, please pick again.");
                    }
                    break;
                    case "2" : {
                        itemOrdered = "NVIDIA 2080TI";
                        System.out.println("Checking if the item is in stock.");
                        if (Math.random() * 10 > 3) {
                            System.out.println("This item is in stock, please proceed to checkout.");
                            ordering = false;
                        }
                        else
                            System.out.println("This item is not in stock, please pick again.");
                    }
                    break;
                    case "3" : {
                        itemOrdered = "Intel i9 9990K";
                        System.out.println("Checking if the item is in stock.");
                        if (Math.random() * 10 > 3) {
                            System.out.println("This item is in stock, please proceed to checkout.");
                            ordering = false;
                        }
                        else
                            System.out.println("This item is not in stock, please pick again.");
                    }
                    break;
                    case "4" : {
                        itemOrdered = "Corsair Gold PSU";
                        System.out.println("Checking if the item is in stock.");
                        if (Math.random() * 10 > 3) {
                            System.out.println("This item is in stock, please proceed to checkout.");
                            ordering = false;
                        }
                        else
                            System.out.println("This item is not in stock, please pick again.");
                    }
                }
            }

                System.out.println("Please Enter your Credit Card Information Below: \n");

            System.out.println("Cardholder Name: ");
            String cardHolderName = userInput.nextLine();

            System.out.println("Credit Card Number: ");
            String cardNumber = userInput.nextLine();
            boolean isInValid = CreditCardValidation.IsCardNotValid(cardNumber);
            while(isInValid)
            {
                String NewNumber = userInput.nextLine();
                cardNumber = NewNumber;
                isInValid = CreditCardValidation.IsCardNotValid(cardNumber);

            }
            boolean number2 = CreditCardValidation.isNumber(cardNumber);
            while(!number2)
            {
                String NewNumber = userInput.nextLine();
                cardNumber = NewNumber;

            }

            System.out.println("Expiry (MMYY): ");
            String cardExp = userInput.nextLine();
            boolean ValidExpiry = CreditCardValidation.isNumber(cardExp);
            while(!ValidExpiry)
            {
                System.out.println("Credit Card Number is not valid please enter a new Number:");
                String NewExp = userInput.nextLine();
                cardExp = NewExp;
                ValidExpiry = CreditCardValidation.isNumber(cardExp);

            }
            boolean Expired = CreditCardValidation.IsCardExpired(cardExp);
            while(Expired)
            {
                String newExpiry = userInput.nextLine();
                cardExp = newExpiry;
                Expired = CreditCardValidation.IsCardExpired(cardExp);
            }


            System.out.println("3 Digit CVV: ");
            String cardCVV = userInput.nextLine();
            boolean ValidCVV = CreditCardValidation.isNumber(cardCVV);
            while(!ValidCVV)
            {
                System.out.println("Credit Card Number is not valid please enter a new Number:");
                String NewCVV = userInput.nextLine();
                cardCVV = NewCVV;
                ValidCVV = CreditCardValidation.isNumber(cardCVV);

            }

            System.out.println("Postal Code: ");
            String PostalCode = userInput.nextLine();
            boolean isValidPostalCode = CreditCardValidation.postalcodeValidation(PostalCode);
            while(!isValidPostalCode)
            {
                String NewPostalCode = userInput.nextLine();
                PostalCode = NewPostalCode;
                isValidPostalCode = CreditCardValidation.postalcodeValidation(PostalCode);
            }

            SecretKey SecKey_gen2 = Utility.genKeyWithSalt(sessionKey, saltString);

            String encrypted_cardHolderName = Utility.encrypt(cardHolderName, SecKey_gen2, ivPS);
            String encrypted_cardNumber = Utility.encrypt(cardNumber, SecKey_gen2, ivPS);
            String encrypted_cardExp = Utility.encrypt(cardExp, SecKey_gen2, ivPS);
            String encrypted_cardCVV = Utility.encrypt(cardCVV, SecKey_gen2, ivPS);
            String encrypted_PostalCode = Utility.encrypt(PostalCode, SecKey_gen2, ivPS);
            String encrypted_itemOrdered = Utility.encrypt(itemOrdered, SecKey_gen2, ivPS);
            System.out.println("encrypted");

            printStr.println(encrypted_cardHolderName);
            printStr.println(encrypted_cardNumber);
            printStr.println(encrypted_cardExp);
            printStr.println(encrypted_cardCVV);
            printStr.println(encrypted_PostalCode);
            printStr.println(encrypted_itemOrdered);

            System.out.println("Credit Card Information has been Securely Transmitted to Seller");

        } catch (IOException i) {
            System.out.println(i);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException | ParseException e) {
            e.printStackTrace();
        }
    }

}
