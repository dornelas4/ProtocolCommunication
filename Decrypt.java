
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.*;

class Decrypt {

    public static void main(String[] args) {
        // This program reads a private key from a file
        // and an encrypted message, decrypts the message
        // and prints it.
        // Written by Luc Longpre for Computer Security, Spring 2018

        File file;
        PrivateKey privKey;
        Cipher cipher;
        byte[] decryptedByteArray;
        String encryptedString, decryptedString;

        // get the private key from file
        privKey = PemUtils.readPrivateKey("privateKey.pem");

        // get the encrypted Message
        try {
            file = new File("encryptedpwdfile.txt");
            Scanner input = new Scanner(file);
            encryptedString = input.nextLine();
            System.out.println("The encrypted string is: " + encryptedString);
        } catch (Exception e) {
            System.out.println("Could not open encryptedMessage file");
            return;
        }
        decryptedByteArray = decrypt(privKey, Base64.getDecoder().decode(encryptedString));
        decryptedString = new String(decryptedByteArray);
        System.out.println("The decrypted string is: " + decryptedString);
    }
    
    //Created a method to get the decrypted bytes
    //Needed for use in echoclientskeleton
    public byte[] getDecryptedBytes( byte[] encryptedBytes) {
		PrivateKey privKey;
		Cipher cipher;
		byte[] decryptedByteArray;
		privKey = PemUtils.readPrivateKey("DanielServerPrivate.pem");
		// decrypt string with private key
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			decryptedByteArray = cipher.doFinal(encryptedBytes);
			return decryptedByteArray;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println("error decrypting");
			e.printStackTrace();
		}
		return null;
	}

    public static byte[] decrypt(PrivateKey privKey, byte[] encryptedByteArray) {
        // decrypts a byte array using a private key
        // and returns the decryption as a byte array
       
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            return cipher.doFinal(encryptedByteArray);      
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("error while decrypting the message");
            return null;
        }
    }
}
