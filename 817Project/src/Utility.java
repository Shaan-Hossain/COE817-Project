
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
	public static SecretKey genKeyWithSalt(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {   
		    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		    return secret;
	}
	
	public static String encrypt(String encryptedMessage, SecretKey SecKey_gen, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		Cipher cipher_DES = Cipher.getInstance("AES/CBC/PKCS5Padding");       
		cipher_DES.init(Cipher.ENCRYPT_MODE, SecKey_gen, iv);              
        byte[] byte_msg = cipher_DES.doFinal(encryptedMessage.getBytes("UTF-8"));      
        String encoded_msg = Base64.getEncoder().encodeToString(byte_msg);    
		return encoded_msg;
	}
	
    public static String decrypt(String encryptedMessage, SecretKey SecKey_gen, IvParameterSpec iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String encrypted_msg = encryptedMessage;
        Cipher cipher_DES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher_DES.init(Cipher.DECRYPT_MODE, SecKey_gen, iv);
        byte[] decode_byte = Base64.getDecoder().decode(encrypted_msg);
        byte[] decrypt_byte = cipher_DES.doFinal(decode_byte);
        String decoded_msg = new String(decrypt_byte);
        return decoded_msg;
    }
	
}
