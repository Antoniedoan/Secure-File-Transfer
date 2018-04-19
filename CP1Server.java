// 1002112 KOK HAN YI Cohort 3
// 1002266 Doan Thanh Cohort 3

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class CP1Server {

	private static String privateKeyFile = "C:/Hanyi/_ISTD2/System-Engineering/ProgAssignment2/Code/ServerFiles/privateServer.der";
	private static String signedCertificateFile = "C:/Hanyi/_ISTD2/System-Engineering/ProgAssignment2/Code/ServerFiles/server.crt";
	private static String ServerFilePath = "C:/Hanyi/_ISTD2/System-Engineering/ProgAssignment2/Code/ServerFiles/";

	public static void main(String[] args) {


		int port = 4321;
		if (args.length > 0)
			port = Integer.parseInt(args[0]);
		if(args.length > 1){
			ServerFilePath = args[1];
			privateKeyFile = ServerFilePath + "privateServer.der";
		}

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		long timeStarted = 0;
		long timeEnded = 0;


		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			//generate private key
			Path privateKeyPath = Paths.get(privateKeyFile);
			byte[] privateKeyByteArray = Files.readAllBytes(privateKeyPath);

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			String hashAlgo = "RSA/ECB/PKCS1Padding";
			while (!connectionSocket.isClosed()) {

				String packetType = fromClient.readUTF();

				// If the packet is for transferring the filename
				if (packetType.equals("filename")) {

					System.out.println("Server: Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream(ServerFilePath + new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

					// If the packet is for transferring a chunk of the file
				} else if (packetType.equals("filechunk")) {

					int numBytes = fromClient.readInt();
					byte [] enblock = new byte[128];
					fromClient.readFully(enblock);

					Cipher decryptor = Cipher.getInstance(hashAlgo);
					decryptor.init(Cipher.DECRYPT_MODE, privateKey);
					//decrypt
					byte[] deblock = decryptor.doFinal(enblock);

					if (numBytes > 0)
						bufferedFileOutputStream.write(deblock, 0, numBytes);

					if (numBytes < 117) {

						timeEnded = System.nanoTime();
						long timeTaken = timeEnded - timeStarted;
						System.out.println("Time Taken: " + timeTaken/1000000000.0 + "s");
						System.out.println("Closing connection...");
						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();

						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				} else if(packetType.equals("firstresponse")){
					//start recording
					timeStarted = System.nanoTime();
					String serverResponse = "Hello, this is SecStore!";
					Cipher enMsg = Cipher.getInstance(hashAlgo);
					enMsg.init(Cipher.ENCRYPT_MODE, privateKey);
					//encrypt response
					byte[] enMsgInByte = enMsg.doFinal(serverResponse.getBytes());

					toClient.writeUTF(hashAlgo);
					System.out.println(fromClient.readUTF());
					toClient.writeInt(enMsgInByte.length);
					toClient.write(enMsgInByte);
					toClient.flush();


				} else if(packetType.equals("cert")){
					toClient.writeUTF("Sending Cert");
					System.out.println("Server: Sending Signed Cert to Client");

					String filename = "server.crt";
					String filepath = ServerFilePath + filename;
					sendFile(toClient,filename,filepath);
				}
				else if(packetType.equals("nonce")){

					//read nonce convert to byte
					int nonceLen = fromClient.readInt();
					System.out.println("Server: Received nonce from client");

					byte[] nonceByte = new byte[nonceLen];
					fromClient.readFully(nonceByte);


					// set private key to encrypt
					Cipher encryptor = Cipher.getInstance(hashAlgo);
					encryptor.init(Cipher.ENCRYPT_MODE, privateKey);

					// encrypt nonce
					byte[] encryptedNonce = encryptor.doFinal(nonceByte);
					// send hashAlgo
					toClient.writeUTF(hashAlgo);
					// send encrypted nonce length
					toClient.writeInt(encryptedNonce.length);
					// send encrypted nonce
					toClient.write(encryptedNonce, 0, encryptedNonce.length);//byte
					toClient.flush();
					System.out.println("Server: Sent encrypted nonce to client");


				}else if(packetType.equals("end")){
					
				}

			}

		} catch (Exception e) {e.printStackTrace();}

	}

	private static void sendFile(DataOutputStream toClient, String filename, String filepath) throws Exception{
		// Send the filename
		toClient.writeInt(filename.getBytes().length);
		toClient.write(filename.getBytes());

		// Open the file
		FileInputStream fileInputStream = new FileInputStream(filepath);
		BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

		byte [] fromFileBuffer = new byte[117];

		// Send the file
		for (boolean fileEnded = false; !fileEnded;) {

			int numBytes = bufferedFileInputStream.read(fromFileBuffer);
			fileEnded = numBytes < 117;


			toClient.writeInt(numBytes);
			toClient.write(fromFileBuffer);
			toClient.flush();
		}
		System.out.println("Server: Cert successfully sent.");
		bufferedFileInputStream.close();
		fileInputStream.close();
	}

	
}

//class SleepThread extends Thread{
//	private long duration;
//	SleepThread(long duration){
//		this.duration = duration;
//	}
//	@Override
//	public void run() {
//		try {
//			Thread.sleep(duration*1000);
//		} catch (InterruptedException e) {
//			e.printStackTrace();
//		}
//	}
//}