
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Utility {
	public static SecretKey getKeyFromPassword(String password, String salt)
		    throws NoSuchAlgorithmException, InvalidKeySpecException {
		    
		    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
		        .getEncoded(), "AES");
		    return secret;
	}
	
	public static String encrypt(String encryptedMessage, SecretKey SecKey_gen, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		Cipher DES_Cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
       
		DES_Cipher2.init(Cipher.ENCRYPT_MODE, SecKey_gen, iv);              
        byte[] Msg_ByteCode = DES_Cipher2.doFinal(encryptedMessage.getBytes("UTF-8"));
        
        String enc_Msg = Base64.getEncoder().encodeToString(Msg_ByteCode);
        
		return enc_Msg;
	}
	
    public static String decrypt(String encryptedMessage, SecretKey SecKey_gen, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String en_Msg = encryptedMessage;

        Cipher DES_Cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        DES_Cipher.init(Cipher.DECRYPT_MODE, SecKey_gen, iv);

        byte[] decByteCode = Base64.getDecoder().decode(en_Msg);
        byte[] deEncByte = DES_Cipher.doFinal(decByteCode);

        String dec_FinalMsg = new String(deEncByte);

        return dec_FinalMsg;
    }
	
}
