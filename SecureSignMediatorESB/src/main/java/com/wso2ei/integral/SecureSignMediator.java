package com.wso2ei.integral;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

//import javax.xml.soap.Node;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext; 
import org.apache.synapse.mediators.AbstractMediator;

public class SecureSignMediator extends AbstractMediator { 
  private static final Log log = LogFactory.getLog(SecureSignMediator.class);
  
  //private Node body;

  public boolean mediate(MessageContext context) { 
    // TODO Implement your mediation logic here 
    try{
	    KeyPair pair = generateKeyPair();
	    OMElement req = context.getEnvelope().getBody().getFirstElement().getFirstElement();
	    log.info("body toString = " + req.toString());
	    //String prop = context.getProperty("name").toString();
	    //log.info("INSIDE MEDIATE property city = " + prop);
	    //context.setProperty("city", "Great" + prop);

	    if(context.isResponse()){
	      log.info("SecureSignMediator entering response");
	      boolean isCorrect = verify(
	          context.getProperty("ResponseBody").toString(),
	          context.getProperty("ResponseSignature").toString(),
	          pair.getPublic()
	          );
	      System.out.println("Signature correct: " + isCorrect);
	      context.setProperty("RESPONSE_SING_ISVALID", isCorrect);
	    } else {
	      log.info("SecureSignMediator entering request");
	      String signature = sign(req.toString(), pair.getPrivate());
	      context.setProperty("SIGN", signature);
	    }
    } catch (Exception ex){
      log.info("SecureSignMediator ERROR: " + ex.getMessage());
      //return false;
    }
    return true;
  }
  
  public static KeyPair generateKeyPair() throws Exception {
	  log.info("generateKeyPair");
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048, new SecureRandom());
      KeyPair pair = generator.generateKeyPair();

      return pair;
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

/*public Node getBody() {
	return body;
}

public void setBody(Node body) {
	this.body = body;
}*/
}