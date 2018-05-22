
import java.io.*;
import java.security.*;

public class CreatePemKeys {

    public static void main(String[] args) {
        // This program creates an RSA key pair, 
        // saves the private key in a file in PEM format named privateKey.pem,
        // saves the public key in a file named publickey.pem.
        // The program uses PemUtils.java.
        // The PemUtils.java uses Base64 encoding, which is available in Java 8.
        // Written by Luc Longpre for Computer Security, Spring 2018

        File file;
        KeyPair key;

        // generate key pair
        try {
            // Initialize a key pair generator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyGen.initialize(1024,random);
            // Generate a key pair
            key = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            // If no provider supports RSA, or the key size is not supported
            System.out.println("Key pair generator failed to generate keys, " + e);
            return;
        }

        PrivateKey privKey = key.getPrivate();
        PublicKey pubKey = key.getPublic();

        try {
            PemUtils.writePublicKey(pubKey, "publicKey.pem");
        } catch (FileNotFoundException e) {
            System.out.println("Write Public Key: File not found Exception");
        }

        try {
            PemUtils.writePrivateKey(privKey, "privateKey.pem");
        } catch (FileNotFoundException e) {
            System.out.println("Write Private Key: File not found Exception");
        }
    }
}
