package org.example;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class BouncyCastleInAES {


  public static void main(String[] args) throws Exception {

    // Add Bouncy Castle as a security provider
    Security.addProvider(new BouncyCastleProvider());

// Generate a random 256-bit key
    KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
    keyGen.init(256);
    SecretKey secretKey = keyGen.generateKey();

    // Sample data to be encrypted
    String plaintext = "Hello, Bouncy Castle AES Encryption!";

    // Encrypt the data
    byte[] encryptedData = encrypt(plaintext.getBytes(), secretKey);
    System.out.println("Encrypted: " + new String(encryptedData));

    // Decrypt the data
    byte[] decryptedData = decrypt(encryptedData, secretKey);
    System.out.println("Decrypted: " + new String(decryptedData));
  }

  //For Encryption
  private static byte[] encrypt(byte[] data, SecretKey key)
      throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("AES", "BC");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
  }
  //For Decryption
  private static byte[] decrypt(byte[] encryptedData, SecretKey key)
      throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    Cipher cipher = Cipher.getInstance("AES", "BC");
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(encryptedData);
  }
}
