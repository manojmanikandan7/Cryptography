import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
public class Encrypt 
{
    public static void encrypt(String strToEncrypt,String sec,String salt) 
    {
        String SECRET_KEY=sec;
        String SALT=salt;
        try 
        {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            System.out.println(Base64.getEncoder()
            .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8))));
        } 
        catch (Exception e) 
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
    }

    public static void main(String args[]){
        Scanner in=new Scanner(System.in);
        System.out.print("Enter the message to be encrypted: ");
        String s=in.nextLine();
        System.out.print("Enter the secret key: ");
        String secret=in.nextLine();
        System.out.print("Enter the salt: ");
        String salt=in.nextLine();
        encrypt(s, secret, salt);
    }
}