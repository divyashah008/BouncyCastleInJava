package org.example;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleInRSA {

  public static void main(String[] args)
      throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

    // Add Bouncy Castle as a security provider
    Security.addProvider(new BouncyCastleProvider());

    // Create a KeyPairGenerator instance for RSA with Bouncy Castle
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");

    // Initialize the KeyPairGenerator with key size (e.g., 2048 bits)
    keyPairGenerator.initialize(2048);

    // Generate RSA key pair
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    PublicKey publicKey=keyPair.getPublic();
    PrivateKey privateKey=keyPair.getPrivate();

    // Display the generated key pair
    System.out.println("Public Key: " + publicKey);
    System.out.println("Private Key: " +privateKey);




    // Sample data to be encrypted
    String plaintext = "Hello, Bouncy Castle RSA Encryption!";

    // Encrypt the text using the public key
    String encryptedText = encrypt(plaintext, publicKey);
    System.out.println("Encrypted Text:"+encryptedText);

    // Decrypt the text using the private key
    String decryptedText = decrypt(encryptedText+"divya", privateKey);
    System.out.println("Decrypted Text:"+decryptedText);
  }
  private static String encrypt(String plainText, PublicKey publicKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
    // Create a cipher object and initialize it with the public key
    Cipher cipher = Cipher.getInstance("RSA","BC");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);

    // Encrypt the text
    byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
    return Base64.getEncoder().encodeToString(encryptedBytes);
  }

  private static String decrypt(String encryptedText, PrivateKey privateKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
    // Create a cipher object and initialize it with the private key
    Cipher cipher = Cipher.getInstance("RSA","BC");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);

    // Decrypt the text
    byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
    return new String(decryptedBytes);
  }

}
