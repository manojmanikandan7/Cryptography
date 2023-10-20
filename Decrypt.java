import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
public class Decrypt 
{
    public static String decrypt(String strToDecrypt,String sec,String salt) 
    {
        String SECRET_KEY = sec;
        String SALT = salt;
        try 
        {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (Exception e) 
        {
            System.out.println("Error while decrypting: " + e.toString());
            return null;
        }
    }
    public static void main(String args[]){
        Scanner in=new Scanner(System.in);
        System.out.print("Enter the message to be decrypted: ");
        String s=in.nextLine();
        System.out.print("Enter the secret key: ");
        String secret=in.nextLine();
        System.out.print("Enter the salt: ");
        String salt=in.nextLine();
        System.out.println(decrypt(s, secret, salt));
    }
}