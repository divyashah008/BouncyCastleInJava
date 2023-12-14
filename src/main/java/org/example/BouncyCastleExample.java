package org.example;

import java.security.PublicKey;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleExample {

  public static void main(String[] args) throws Exception {
    // Add Bouncy Castle as a security provider
    Security.addProvider(new BouncyCastleProvider());


    // Create a KeyPairGenerator instance for RSA with Bouncy Castle
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");

    // Initialize the KeyPairGenerator with key size (e.g., 2048 bits)
    keyPairGenerator.initialize(2048);

    // Generate RSA key pair
    KeyPair keyPair = keyPairGenerator.generateKeyPair();


    // Display the generated key pair
    System.out.println("Public Key: " + keyPair.getPublic());
    System.out.println("Private Key: " + keyPair.getPrivate());

    PublicKey publicKey=keyPair.getPublic();
    PrivateKey privateKey=keyPair.getPrivate();

    // Create a Signature object
    Signature signature = Signature.getInstance("SHA256withRSA", "BC");
    signature.initSign(privateKey);

    // Data to be signed
    byte[] data = "YourDataToSign".getBytes();

    // Update the Signature object with the data
    signature.update(data);

    // Generate the digital signature
    byte[] digitalSignature = signature.sign();

    // Verify the signature
    Signature verifier = Signature.getInstance("SHA256withRSA", "BC");
    verifier.initVerify(publicKey);
    verifier.update(data);

    boolean isSignatureValid = verifier.verify(digitalSignature);
    System.out.println("Is Signature Valid? " + isSignatureValid);
  }
  }

