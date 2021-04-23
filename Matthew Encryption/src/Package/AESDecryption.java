package Package;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


public class AESDecryption {
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String ALGORITHM = "AES";

    public void prepareSecreteKey(String myKey) {
        MessageDigest Provider = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            Provider = MessageDigest.getInstance("SHA-1");
            key = Provider.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String decrypt(String strToDecrypt, String secret) 
    {
        try {
            prepareSecreteKey(secret);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String[] args) 
    {
    			
    		    Scanner encryptedStringScan = new Scanner(System.in); 
    		    Scanner secretKeyScan = new Scanner(System.in); 
    		    System.out.println("Welcome to the decryption application!");
    		    System.out.println("");
    		    System.out.println("Please follow the on-screen prompts in order to decrypt your message.");
    		    System.out.println("You will need both the encrypted string and decryption key.");
    		    System.out.println("----------------------------------");
    		    System.out.println("Please enter the string you want decrypted!");
    		    String encryptedString = (encryptedStringScan.nextLine());
    		    System.out.println("Please enter the key for the encypted string!");
    		    String secretKey = (secretKeyScan.nextLine());
    		    System.out.println("Decrypting " + encryptedString + " with the private key " + secretKey);
    		    encryptedStringScan.close();
    		    secretKeyScan.close();
    		    
    		  
        AESDecryption aesEncryptionDecryption = new AESDecryption();
        String decryptedString = aesEncryptionDecryption.decrypt(encryptedString, secretKey);

        System.out.println("Decrypted string: "+ decryptedString);
    }
}