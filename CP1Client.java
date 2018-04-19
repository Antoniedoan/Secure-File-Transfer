//Doan Thanh 1002266
//Kok Hanyi 1002112

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CP1Client {

    public static void main(String[] args) {

        String serverCert = "server.crt" ;
        String caCert = "/Users/doanthanh/Downloads/PA2/OriginalKey/CA.crt";
        String filePath = "/Users/doanthanh/Downloads/PA2/files";
        String theFile = "/Users/doanthanh/Downloads/PA2/files/small.txt";
        String sentFilename = "small.txt";
        String fileLocation = "/Users/doanthanh/Downloads/PA2/src/";
        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        String serverAddress = "10.12.146.166";
        if (args.length > 1) serverAddress = args[1];


        if (args.length > 2) {
            fileLocation = args[2];
            caCert=fileLocation+"CA.crt";

        }
        if (args.length>3){
            theFile=fileLocation+args[3];
        }

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedOutputStream = null;
        BufferedInputStream bufferedFileInputStream = null;


        try {

            //***************************AP************************************

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());


            //initiate handshake with server
            //str == 'msg' means talking to server
            toServer.writeUTF("firstresponse");
            toServer.writeUTF(">>Client: Hello SecStore, please prove your identity!");
            String hashAlgo = fromServer.readUTF();
            int serverResponseLen = fromServer.readInt();

            byte[] serverResponse = new byte[serverResponseLen];
            fromServer.readFully(serverResponse);


            //************************* NONCE *****************************
            toServer.writeUTF("nonce");
            //generate nonce
            SecureRandom secureRandom = new SecureRandom();
            //BigInteger nonce = new BigInteger(128, secureRandom);

            byte[] nonceByte = new byte[117];
            secureRandom.nextBytes(nonceByte);

            //send nonce over
            toServer.writeInt(nonceByte.length);
            toServer.write(nonceByte);
            System.out.println("Client: Send nonce to server");

            //get encrypted type
            String hashAlgo1 = fromServer.readUTF();
            //get encrypted nonce length
            int encryptedNonceLength = fromServer.readInt();

            //get encrypted nonce byte
            byte[] encryptedNonceInByte = new byte[encryptedNonceLength];

            fromServer.readFully(encryptedNonceInByte);
            System.out.println("Client: Received encrypted nonce from server");


            //receive server.crt
            toServer.writeUTF("cert");
            toServer.writeUTF(">>Client: Please send me your certificate signed by the CA");
            String serverResponse1 = fromServer.readUTF();
            System.out.println("Response from Server: " + serverResponse1);

            String serverCertPath = receiveFile(fromServer, filePath);

            //**************************Verifying server cert************************

            //Extract CA cert's public key
            FileInputStream CAInputStream = new FileInputStream(caCert);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(CAInputStream);
            PublicKey CApublicKey = certificate.getPublicKey();
            System.out.println("Public key from CA certificate extracted.");
            CAInputStream.close();

            //Verify signed cert
            FileInputStream signedServerCert  = new FileInputStream(serverCertPath);

            X509Certificate signedCertificate = (X509Certificate) certificateFactory.generateCertificate(signedServerCert);
            signedCertificate.checkValidity();
            signedCertificate.verify(CApublicKey);
            System.out.println("Signed Certificate validated and verified successfully");

            //get public key from Signed cert
            PublicKey serverPublicKey = signedCertificate.getPublicKey();

            //**************************Decrypting items***********************
            //decrypt first response from server
            Cipher deMsg = Cipher.getInstance(hashAlgo);
            deMsg.init(Cipher.DECRYPT_MODE, serverPublicKey);

            byte[] decryptedResponse = deMsg.doFinal(serverResponse);

            System.out.println("Response from Server: "+ new String(decryptedResponse));

            //create cipher object and initialise to decrypt mode using extracted server public key
            Cipher deCipher = Cipher.getInstance(hashAlgo);
            deCipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            //decrypt nonce
            byte[] decryptedNonce = deCipher.doFinal(encryptedNonceInByte);

            //final verification step
            if ((new String(nonceByte)).equals(new String(decryptedNonce))){
                System.out.println("Server successfully verified!");
                toServer.writeUTF("msg");
                toServer.writeUTF(">>Client: Ready to upload file.");
            } else {
                System.out.println("Unsuccessful Server Verification, closing all connections.");
            }

        //***************************Send secure file************************
            System.out.println("Sending file...");

            // Send the filename
            toServer.writeUTF("filename");
            toServer.writeInt(sentFilename.getBytes().length);
            toServer.write(sentFilename.getBytes());
            //toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(theFile);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];

            // Send the file
            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;

                Cipher enFile = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                enFile.init(Cipher.ENCRYPT_MODE, serverPublicKey);

                byte[] encryptedFile = enFile.doFinal(fromFileBuffer);

                toServer.writeUTF("filechunk");
                toServer.writeInt(numBytes);

                toServer.write(encryptedFile);
                toServer.flush();
            }
            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("File sent!");
            System.out.println("Closing connection...");


        } catch (Exception e) {e.printStackTrace();}
    }

    private static String receiveFile(DataInputStream fromServer, String filepath) throws Exception{
        int fileLen = fromServer.readInt();

        byte[] filenameInByte = new byte[fileLen];
        fromServer.readFully(filenameInByte, 0, fileLen);

        System.out.println("Receiving file...");

        // Must use read fully!
        // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
        String filename = new String(filenameInByte, 0, fileLen);
        FileOutputStream fileOutputStream = new FileOutputStream(filepath + filename);
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
        boolean running = true;
        while (running) {

            int lineLen = fromServer.readInt();

            byte[] block = new byte[lineLen];
            fromServer.readFully(block, 0, lineLen);

            if (lineLen > 0)
                bufferedOutputStream.write(block, 0, lineLen);

            if (lineLen < 117) {
                System.out.println("Cert received.");
                if (bufferedOutputStream != null) bufferedOutputStream.close();
                if (bufferedOutputStream != null) fileOutputStream.close();
                running = false;
            }
        }
        return filepath+filename;
    }
}

