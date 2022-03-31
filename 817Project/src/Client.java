
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

        Cipher c_rCipher;
        PublicKey publicK_A, publicK_B;
        PrivateKey privateK_A;
        KeyPair keyPair_A;
        KeyPairGenerator keyPairGen_A;
        int Socket_Port = 10001;
        String IDa = "Initiator A";
        String sessionKey;

        System.out.println("====================");
        System.out.println("| Payment Terminal |");
        System.out.println("====================");

        Socket ss = new Socket("localhost", Socket_Port);
        Scanner serverInput = new Scanner(ss.getInputStream());
        Scanner userInput = new Scanner(System.in);
        System.out.println("Successfully Connected to Seller's Terminal");
        PrintStream printStr = new PrintStream(ss.getOutputStream());

        try{
            keyPairGen_A = KeyPairGenerator.getInstance("RSA");
            keyPair_A = keyPairGen_A.generateKeyPair();
            publicK_A = keyPair_A.getPublic();
            privateK_A = keyPair_A.getPrivate();
            String publicKeyString_B = serverInput.nextLine();
            byte [] key_ByteCodeB = Base64.getDecoder().decode(publicKeyString_B);
            X509EncodedKeySpec X509KeySpec = new X509EncodedKeySpec(key_ByteCodeB);
            publicK_B = KeyFactory.getInstance("RSA").generatePublic(X509KeySpec);
            c_rCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c_rCipher.init(Cipher.ENCRYPT_MODE,publicK_B);

            SimpleDateFormat dateFormat2 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String A_Date = dateFormat2.format(new Date());
            byte[] c_iDAByteCode = c_rCipher.doFinal(IDa.getBytes("UTF-8"));
            byte[] c_NAByteCode = c_rCipher.doFinal(A_Date.getBytes("UTF-8"));

            String enc_IDa = Base64.getEncoder().encodeToString(c_iDAByteCode);
            String enc_nA = Base64.getEncoder().encodeToString(c_NAByteCode);
            printStr.println(enc_IDa);
            printStr.println(enc_nA);
            String public_A = Base64.getEncoder().encodeToString(publicK_A.getEncoded());
            printStr.println(public_A);
            String A_Nonce = serverInput.nextLine();
            String B_Nonce = serverInput.nextLine();
            c_rCipher.init(Cipher.DECRYPT_MODE, privateK_A);
            byte[] nA_ByteCode = Base64.getDecoder().decode(A_Nonce);
            byte[] nB_ByteCode = Base64.getDecoder().decode(B_Nonce);
            A_Nonce = new String(c_rCipher.doFinal(nA_ByteCode));
            B_Nonce = new String(c_rCipher.doFinal(nB_ByteCode));

            c_rCipher.init(Cipher.ENCRYPT_MODE, publicK_B);
            nB_ByteCode = c_rCipher.doFinal(B_Nonce.getBytes("UTF-8"));
            String nB_Encrypted = Base64.getEncoder().encodeToString(nB_ByteCode);
            printStr.println(nB_Encrypted);

            SecureRandom random = new SecureRandom();
            byte bytes[] = new byte[20];
            random.nextBytes(bytes);
            sessionKey = Base64.getEncoder().encodeToString(bytes);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);
            String iv = ivParameterSpec.toString();

            byte[] salt = new byte[10];
            random.nextBytes(salt);
            String saltString = Base64.getEncoder().encodeToString(salt);

            char[] charSessionKey = new char[sessionKey.length()];
            System.out.println("Session Key: "+ sessionKey);
            System.out.println("Salt: "+ saltString);
            System.out.println("iv: "+ ivParameterSpec);

            byte[] ivByte = c_rCipher.doFinal(iv.getBytes("UTF-8"));
            byte[] SeshKey_ByteCode = c_rCipher.doFinal(sessionKey.getBytes("UTF-8"));
            byte[] saltByteCode = c_rCipher.doFinal(saltString.getBytes("UTF-8"));
            String enc_SKByteCode = Base64.getEncoder().encodeToString(SeshKey_ByteCode);
            String enc_saltByteCode = Base64.getEncoder().encodeToString(saltByteCode);
            String enc_ivByteCode = Base64.getEncoder().encodeToString(ivByte);

            printStr.println(enc_SKByteCode);
            printStr.println(enc_saltByteCode);
            printStr.println(enc_ivByteCode);

            boolean ordering = true;
            String itemOrdered = "";

            while (ordering) {
                System.out.println("Which item would you like to purchase?");
                System.out.println("1. Prebuilt PC");
                System.out.println("2. NVIDIA 2080TI");
                System.out.println("3. Intel i9 9990K");
                System.out.println("4. Corsair Gold PSU");
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

            SecretKey SecKey_gen2 = Utility.getKeyFromPassword(sessionKey, saltString);

            String enc_cardHolderName = Utility.encrypt(cardHolderName, SecKey_gen2, ivParameterSpec);
            String enc_cardNumber = Utility.encrypt(cardNumber, SecKey_gen2, ivParameterSpec);
            String enc_cardExp = Utility.encrypt(cardExp, SecKey_gen2, ivParameterSpec);
            String enc_cardCVV = Utility.encrypt(cardCVV, SecKey_gen2, ivParameterSpec);
            String enc_PostalCode = Utility.encrypt(PostalCode, SecKey_gen2, ivParameterSpec);
            String enc_itemOrdered = Utility.encrypt(itemOrdered, SecKey_gen2, ivParameterSpec);
            System.out.println("encrypted");

            printStr.println(enc_cardHolderName);
            printStr.println(enc_cardNumber);
            printStr.println(enc_cardExp);
            printStr.println(enc_cardCVV);
            printStr.println(enc_PostalCode);
            printStr.println(enc_itemOrdered);

            System.out.println("Credit Card Information has been Securely Transmitted to Seller");

        } catch (IOException i) {
            System.out.println(i);
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | InvalidKeySpecException | InvalidAlgorithmParameterException | ParseException e) {
            e.printStackTrace();
        }
    }

}
