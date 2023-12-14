package org.example;
import java.math.BigInteger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;


public class BouncyDataIntegrity {

    public static void main(String[] args) throws Exception {
      Security.addProvider(new BouncyCastleProvider());

      // Generate AES key
      SecretKey aesKey = generateAESKey();

      // Generate RSA key pair
      AsymmetricCipherKeyPair rsaKeyPair = generateRSAKeyPair();

      // Encrypt AES key using RSA public key
      byte[] encryptedAesKey = encryptRSA(aesKey.getEncoded(),
          (RSAKeyParameters) rsaKeyPair.getPublic());

      // Decrypt AES key using RSA private key
      SecretKey decryptedAesKey = decryptRSA(encryptedAesKey,
          (RSAKeyParameters) rsaKeyPair.getPrivate());

      // Encrypt data using AES
      String plaintext = "Hello, Bouncy Castle!";
      byte[] encryptedData = encryptAES(plaintext, aesKey);

      // Decrypt data using the decrypted AES key
      String decryptedData = decryptAES(encryptedData, decryptedAesKey);

      System.out.println("Original Data: " + plaintext);
      System.out.println("Decrypted Data: " + decryptedData);
    }

    private static SecretKey generateAESKey()
        throws NoSuchAlgorithmException, NoSuchProviderException {
      KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
      keyGen.init(256); // You can change the key size as needed
      return keyGen.generateKey();
    }

    private static byte[] encryptAES(String plaintext, SecretKey aesKey) throws Exception {
      Cipher cipher = Cipher.getInstance("AES", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, aesKey);
      return cipher.doFinal(plaintext.getBytes());
    }

    private static AsymmetricCipherKeyPair generateRSAKeyPair() {
      RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
      generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 2048, 80));
      return generator.generateKeyPair();
    }

    private static byte[] encryptRSA(byte[] data, RSAKeyParameters publicKey)
        throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
      Cipher cipher = Cipher.getInstance("RSA", "BC");
      cipher.init(Cipher.ENCRYPT_MODE, (Key) publicKey);
      return cipher.doFinal(data);
    }

    private static SecretKey decryptRSA(byte[] encryptedAesKey, RSAKeyParameters privateKey) throws Exception {
      Cipher cipher = Cipher.getInstance("RSA", "BC");
      cipher.init(Cipher.DECRYPT_MODE, (Key) privateKey);
      byte[] decryptedAesKey = cipher.doFinal(encryptedAesKey);
      return new SecretKeySpec(decryptedAesKey, "AES");
    }

    private static String decryptAES(byte[] encryptedData, SecretKey aesKey) throws Exception {
      Cipher cipher = Cipher.getInstance("AES", "BC");
      cipher.init(Cipher.DECRYPT_MODE, aesKey);
      byte[] decryptedBytes = cipher.doFinal(encryptedData);
      return new String(decryptedBytes);
    }

}
