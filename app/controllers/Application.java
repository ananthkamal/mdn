package controllers;

import play.*;
import play.libs.WS;
import play.libs.WS.HttpResponse;
import play.mvc.*;
import play.mvc.results.RenderHtml;
import sun.misc.BASE64Decoder;

import java.io.UnsupportedEncodingException;
import java.net.HttpCookie;
import java.net.URLDecoder;
import java.security.Key;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.ning.http.util.Base64;

import models.*;

public class Application extends Controller {
	
	public static final String AUTHORIZATION_ENDPOINT = "http://144.28.178.26:8080/visp-openid-connect-server/authorize";
	private static final String ALGO = "AES";
	private static final String MDN_VDN_SECRET = Play.configuration.getProperty("mdn.vdn.secret");

    public static void index() {
        render();
    }
    
    public static void getMdn() throws Exception {
    	
    	//Extract the encrypted mdn from the request header
    	String encryptedData = Http.Request.current().headers.get("x-zinfo").toString();
    	if(encryptedData == null){
    		renderJSON("{No x-zinfo header received}");
    	}
    	
    	/* received urlsafe base64 text.
  	  	convert first to normal base64 and then to base64 decode */
    	String base64EncryptedMdn = URLDecoder.decode(encryptedData, "UTF-8");
    	byte[] encryptedMdn = Base64.decode(base64EncryptedMdn);
    	
    	//Key to decrypt the encrypted mdn
    	//Needs to be implemented to get the actual key 
    	//byte[] secret = new byte[]{'s','e','c','r','e','t'};
    	byte[] secret = MDN_VDN_SECRET.getBytes();
    	
    	//Call decrypt method to get the decrypted mdn
    	String mdn = decrypt(encryptedMdn.toString(), secret);
    	
    	//Sets a cookie in the response
    	Http.Response.current().setCookie("mdn", mdn);
    	renderJSON("{mdn:"+mdn+"}");
    	
    }
    
    public static String decrypt(String encryptedData, byte[] secret) throws Exception {
        Key key = generateKey(secret);
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedValue = new BASE64Decoder().decodeBuffer(encryptedData);
        byte[] decValue = c.doFinal(decodedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
    
    private static Key generateKey(byte[] secret) throws Exception {
	        Key key = new SecretKeySpec(secret, ALGO);
	        return key;
	}

}



/*String mdnParam = "&mdn=1234567890";
String forwardUrl = Application.AUTHORIZATION_ENDPOINT+ "?" + Http.Request.current().querystring + mdnParam;
System.out.println(forwardUrl);
HttpResponse resFromAuthServer = WS.url(forwardUrl).get();
System.out.println(resFromAuthServer.toString());*/