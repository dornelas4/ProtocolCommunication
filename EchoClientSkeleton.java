

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class EchoClientSkeleton {
	// This code includes socket code originally provided
	// by Dr. Yoonsik Cheon at least 10 years ago.
	// This version used for Computer Security, Spring 2018.    
	public static void main(String[] args) {

		//String host = "localhost";
		String host = "cspl000.utep.edu";
		BufferedReader in; // for reading strings from socket
		PrintWriter out;   // for writing strings to socket
		ObjectInputStream objectInput;   // for reading objects from socket        
		ObjectOutputStream objectOutput; // for writing objects to socket
		Cipher cipheRSA, cipherEnc;
		byte[] clientRandomBytes;
		byte[] serverRandomBytes;
		PublicKey[] pkpair;
		Cipher cipherDec;
		Socket socket;
		/* Instantiating classes needed to help the client*/
		VerifyCert verifycert = new VerifyCert();
		Verify verify = new Verify();
		Decrypt decrypt = new Decrypt();
		Sign sign = new Sign();
		Encrypt encrypt = new Encrypt();
		PrivateKey privKey = PemUtils.readPrivateKey("DanielServerPrivate.pem");
		// Handshake
		try {
			// socket initialization
			socket = new Socket(host, 8008);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
		} catch (IOException e) {
			System.out.println("socket initialization error");
			return;
		}
		// Send hello to server
		out.println("hello");
		out.flush();
		// Receive Server certificate
		//VERIFY CERTIFICATE AND EXTRACT PUBLIC KEYS DANIEL ORNELAS
		pkpair = verifycert.vCert(in);
		if (pkpair==null)
			System.out.println("certificate verification failed");
		else
			System.out.println("certificate verification succeeded");  

		try {   
			// read and send certificate to server
			//Using the certificate I created
			File file = new File("certificate.txt");
			Scanner input = new Scanner(file);
			String line;
			while (input.hasNextLine()) {
				line = input.nextLine();
				out.println(line);
			}
			out.flush();
		} catch (FileNotFoundException e){
			System.out.println("certificate file not found");
			return;
		}
		try {
			// initialize object streams
			objectOutput = new ObjectOutputStream(socket.getOutputStream());
			objectInput = new ObjectInputStream(socket.getInputStream());
			// receive encrypted random bytes from server
			byte[] encryptedBytes = (byte[]) objectInput.readObject();
			// receive signature of hash of random bytes from server
			byte[] signatureBytes = (byte[]) objectInput.readObject();

			//Decrypt the bytes from the server
			serverRandomBytes = decrypt.getDecryptedBytes(encryptedBytes);
			//SHA256 Encryption
			byte[] serverHashedBytes = SHA256(serverRandomBytes);
			//Verify bytes
			verify.verify(pkpair[1], serverHashedBytes, signatureBytes);
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException  ex) { 
			System.out.println("Problem with receiving random bytes from server");
			return;
		} 
		// generate random bytes for shared secret
		clientRandomBytes = new byte[8];
		// the next line would initialize the byte array to random values
		new Random().nextBytes(clientRandomBytes);
		try {
			//get encrypted bytes
			byte[] encryptedBytes = encrypt.getEncryptedBytes(pkpair[0], clientRandomBytes);
			//send to server
			objectOutput.writeObject(encryptedBytes);
			//hash the bytes
			byte[] hashClientBytes = SHA256(clientRandomBytes);
			privKey = PemUtils.readPrivateKey("DanielPrivateSignClient.pem");
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(privKey);
			sig.update(hashClientBytes);
			//sign the hashed bytes
			byte[] signatureBytes = sig.sign();
			//send bytes
			objectOutput.writeObject(signatureBytes);
		} catch (IOException | SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
			System.out.println("error computing or sending the signature for random bytes");
			return;
		}
		// initialize the shared secret with all zeroes
		// will need to generate from a combination of the server and 
		// the client random bytes generated
		byte[] sharedSecret = new byte[16];
		System.arraycopy(serverRandomBytes, 0, sharedSecret, 0, 8);
		System.arraycopy(clientRandomBytes, 0, sharedSecret, 8, 8);
		
		try {
			// we will use AES encryption, CBC chaining and PCS5 block padding
			cipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
			// generate an AES key derived from randomBytes array
			SecretKeySpec secretKey = new SecretKeySpec(sharedSecret, "AES");
			cipherEnc.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] iv = cipherEnc.getIV();
			//receive client initialization vector
			byte[] decIV = (byte[]) objectInput.readObject();
			cipherDec.init(Cipher.DECRYPT_MODE, secretKey,new IvParameterSpec(decIV));
			objectOutput.writeObject(iv);
		} catch (IOException | NoSuchAlgorithmException 
				| NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ClassNotFoundException   e) {
			System.out.println("error setting up the AES encryption");
			return;
		}
		try {
			// Encrypted communication
			System.out.println("Starting messages to the server. Type messages, type BYE to end");    
			Scanner userInput = new Scanner(System.in);
			boolean done = false;
			while (!done) {
				// Read message from the user
				String userStr = userInput.nextLine();
				// Encrypt the message
				byte[] encryptedBytes = cipherEnc.doFinal(userStr.getBytes());
				// Send encrypted message as an object to the server
				objectOutput.writeObject(encryptedBytes);
				// If user says "BYE", end session
				if (userStr.trim().equals("BYE")) {
					System.out.println("client session ended");
					done = true;
				} else {
					// Wait for reply from server,
					
					encryptedBytes = (byte[]) objectInput.readObject();
					String str = new String(cipherDec.doFinal(encryptedBytes));

					System.out.println( str);
				}
			}            
		} catch (IllegalBlockSizeException | BadPaddingException 
				| IOException | ClassNotFoundException   e) {
			System.out.println("error in encrypted communication with server");
		} 
	}
	//SHA256 Hash
	public static byte[] SHA256(byte[] random) throws NoSuchAlgorithmException{
		MessageDigest hashing = MessageDigest.getInstance("SHA-256");
		hashing.update(random);
		byte[] hashedBytes = hashing.digest();
		return hashedBytes;
	}
}
