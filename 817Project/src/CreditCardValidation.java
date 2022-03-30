import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CreditCardValidation {

    public static boolean isNumber(String str) {
            double v = Double.parseDouble(str);
            if(v>0)return true;
            else return false;
    }
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
    public static boolean IsCardNotValid(String number) {
        int length = String.valueOf(number).length();
        if(length == 16)
            return false;
        else{
                System.out.println("Credit Card Number is not valid please enter a 16 digit Number:");
                return true;
        }
    }

    public static boolean postalcodeValidation(String input){

        String regex = "^(?!.*[DFIOQU])[A-Z][0-9][A-Z] ?[0-9][A-Z][0-9]$";

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        if(matcher.matches())
            return true;
        else{
            System.out.println("Postal code is Invalid Please Enter a valid postal code:");
            return false;
        }




    }

    public static boolean IsCardExpired(String ExpiryInput) throws ParseException {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("MMYY");
        simpleDateFormat.setLenient(false);
        Date expiry = simpleDateFormat.parse(ExpiryInput);
        boolean expired = expiry.before(new Date());
        if (expired == true)
        {
            System.out.println("This card has already expired Please Try Again:");
            return true;
        }
        return false;
    }

}
