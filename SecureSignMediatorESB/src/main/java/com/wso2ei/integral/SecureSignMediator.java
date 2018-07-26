package com.wso2ei.integral;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.xml.namespace.QName;

//import javax.xml.soap.Node;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext; 
import org.apache.synapse.mediators.AbstractMediator;

public class SecureSignMediator extends AbstractMediator { 
  private static final Log log = LogFactory.getLog(SecureSignMediator.class);
  private String PUBLIC_KEY_PATH = "";
  private String PRIVATE_KEY_PATH = "";
  private RSAPrivateKey privateKey;
  private RSAPublicKey publicKey;
  
  //private Node body;

  public boolean mediate(MessageContext context) { 
    // TODO Implement your mediation logic here 
    try{
    	PUBLIC_KEY_PATH = context.getProperty("PUBLIC_KEY_PATH").toString();
    	PRIVATE_KEY_PATH = context.getProperty("PRIVATE_KEY_PATH").toString();
	    //KeyPair pair = generateKeyPair();
	    OMElement req = context.getEnvelope().getBody().getFirstElement().getFirstElement();
	    log.info("body toString = " + req.toString());
	    //String prop = context.getProperty("name").toString();
	    //log.info("INSIDE MEDIATE property city = " + prop);
	    //context.setProperty("city", "Great" + prop);
	    setPrivateKey((RSAPrivateKey) importPrivate());
	    log.info("privateKey set = " + privateKey.getFormat() + " " + privateKey.getAlgorithm());
	    setPublicKey((RSAPublicKey) importPublic());
	    log.info("publicKey set = " + publicKey.getFormat() + " " + publicKey.getAlgorithm());

	    if(context.isResponse()){
	      log.info("SecureSignMediator entering response");
	      OMElement respSign = context.getEnvelope().getBody().getFirstElement().getFirstChildWithName(new QName("SignMsg"));
	      boolean isCorrect = verify(
	    		  req.toString(),
	    		  respSign.toString(),
	          this.getPublicKey()
	          );
	      System.out.println("Signature correct: " + isCorrect);
	      context.setProperty("RESPONSE_SING_ISVALID", isCorrect);
	    } else {
	      log.info("SecureSignMediator entering request");
	      String signature = sign(req.toString(), this.getPrivateKey());
	      context.setProperty("SIGN", signature);
	    }
    } catch (Exception ex){
      log.info("SecureSignMediator ERROR: " + ex.getMessage());
      //return false;
    }
    return true;
  }
  
/*  public static KeyPair generateKeyPair() throws Exception {
	  log.info("generateKeyPair");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048, new SecureRandom());
      KeyPair pair = generator.generateKeyPair();

      return pair;
  }*/
  
  public PrivateKey importPrivate() throws Exception {
	  File f = new File(PRIVATE_KEY_PATH);
	  log.info("private file: " + f.getAbsolutePath());
	  log.info("private file exists: " + f.exists());
	    FileInputStream fis = new FileInputStream(f);
	    DataInputStream dis = new DataInputStream(fis);
	    byte[] keyBytes = new byte[(int)f.length()];
	    dis.readFully(keyBytes);
	    dis.close();
	    //byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		    PKCS8EncodedKeySpec spec =
		      new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePrivate(spec);
  }
  
  public PublicKey importPublic()  throws Exception {
	  File f = new File(PUBLIC_KEY_PATH);
	  log.info("public file: " + f.getAbsolutePath());
	  log.info("public file exists: " + f.exists());
	    FileInputStream fis = new FileInputStream(f);
	    DataInputStream dis = new DataInputStream(fis);
	    byte[] keyBytes = new byte[(int)f.length()];
	    dis.readFully(keyBytes);
	    dis.close();
		    //byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		    X509EncodedKeySpec spec =
		      new X509EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePublic(spec);
		  }
  
  public static String sign(String requestText, PrivateKey privateKey) throws Exception {
	  log.info("sign");
      Signature privateSignature = Signature.getInstance("SHA1withRSA");
      privateSignature.initSign(privateKey);
      privateSignature.update(requestText.getBytes("Windows-1251"));

      byte[] signature = privateSignature.sign();

      return Base64.getEncoder().encodeToString(signature);
  }
  
  public static boolean verify(String responseText, String signature, PublicKey publicKey) throws Exception {
	  log.info("verify");
      Signature publicSignature = Signature.getInstance("SHA1withRSA");
      publicSignature.initVerify(publicKey);
      publicSignature.update(responseText.getBytes("Windows-1251"));

      byte[] signatureBytes = Base64.getDecoder().decode(signature);

      return publicSignature.verify(signatureBytes);
  }

private PrivateKey getPrivateKey() {
	return privateKey;
}

private void setPrivateKey(RSAPrivateKey privateKey) {
	this.privateKey = privateKey;
}

private PublicKey getPublicKey() {
	return publicKey;
}

private void setPublicKey(RSAPublicKey publicKey) {
	this.publicKey = publicKey;
}

}