package main;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.security.auth.x500.X500Principal;
import javax.swing.JOptionPane;

import sun.security.pkcs.PKCS10;
import sun.security.x509.X500Name;
//import sun.security.pkcs.PKCS10;
//import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;



public class CRSGenerator {
	
	private static PublicKey publicKey = null;
    private static PrivateKey privateKey = null;
    private static KeyPairGenerator keyGen = null;
    private static CRSGenerator gcsr = null;

    private CRSGenerator() {
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keypair = keyGen.generateKeyPair();
        publicKey = keypair.getPublic();
        privateKey = keypair.getPrivate();
    }

    public static CRSGenerator getInstance() {
        if (gcsr == null)
            gcsr = new CRSGenerator();
        return gcsr;
    }
    public String getCSR(String cn, String c, String ca, String cb, String cc, String cd) throws Exception {
        byte[] csr = generatePKCS10(cn, c, ca, cb, cc, cd);
        return new String(csr);
    }

   
    private static byte[] generatePKCS10(String CN, String OU, String O,
            String L, String S, String C) throws Exception {
        // generate PKCS10 certificate request
        String sigAlg = "MD5WithRSA";
        PKCS10 pkcs10 = new PKCS10(publicKey);
        
        Signature signature = Signature.getInstance(sigAlg);
        signature.initSign(privateKey);
        
        X500Principal principal = new X500Principal("CN="+CN+", OU="+OU+", O="+O+", C="+C+"");

    
        X500Name x500name=null;
        x500name= new X500Name(principal.getEncoded());
        pkcs10.encodeAndSign(new X500Signer(signature, x500name));
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        pkcs10.print(ps);
        byte[] c = bs.toByteArray();
        try {
            if (ps != null)
                ps.close();
            if (bs != null)
                bs.close();
        } catch (Throwable th) {
        }
        return c;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static void main(String[] args) throws Exception {
        CRSGenerator gcsr = CRSGenerator.getInstance();

        System.out.println("Public Key:\n"+gcsr.getPublicKey().toString());

        System.out.println("Private Key:\n"+gcsr.getPrivateKey().toString());
        String csr = gcsr.getCSR(args[0], args[1], args[2], args[3], args[4], args[5]);
        
        File file = new File(System.getProperty("user.home"), "Desktop/fajl.crs");

        // if file doesnt exists, then create it
        if (!file.exists()) {
            file.createNewFile();
        }

        FileWriter fw = new FileWriter(file.getAbsoluteFile());
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(csr);
        bw.close();

   
        
        
        
        System.out.println("CSR Request Generated!!");
        System.out.println(csr);
    }
    
	}

