package Package;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionDecryption
{
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String ALGORITHM = "AES";

    public void prepareSecreteKey(String myKey) {
        MessageDigest Provider = null;
        try 
        {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            Provider = MessageDigest.getInstance("SHA-1");
            key = Provider.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, ALGORITHM);
        } catch (NoSuchAlgorithmException e) 
        {
            e.printStackTrace();
        }
    }

    public String encrypt(String strToEncrypt, String secret) 
    {
        try {
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
         System.out.println(e.toString());
        }
        return null;
    }

    public static void main(String[] args) throws Exception 
    {
    			
    		    Scanner originalStringScan = new Scanner(System.in); 
    		    Scanner secretKeyScan = new Scanner(System.in); 
    		    System.out.println("Welcome to the encryption application!");
    		    System.out.println("");
    		    System.out.println("To encrypt your message please follow the on-screen prompts.");
    		    System.out.println("Remember to save your decryption key for use with the decryption application.");
    		    System.out.println("----------------------------------");
    		    System.out.println("Please enter the string you want encrypted!");
    		    String originalString = (originalStringScan.nextLine());
    		    System.out.println("Please enter the secret key you want!,");
    		    String secretKey = (secretKeyScan.nextLine());
    		    originalStringScan.close();
    		    secretKeyScan.close();
    		    
	  
        AESEncryptionDecryption aesEncryptionDecryption = new AESEncryptionDecryption();
        String encryptedString = aesEncryptionDecryption.encrypt(originalString, secretKey);

        System.out.println("Decrption key: " + secretKey);
        System.out.println("Encrpted String: " + encryptedString);
    }
}