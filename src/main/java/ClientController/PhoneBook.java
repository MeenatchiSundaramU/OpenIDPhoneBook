package ClientController;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import ClientDAO.PhoneBookDAO;
import ClientModel.authCodeProcessModel;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

public class PhoneBook extends HttpServlet
{
	protected void service(HttpServletRequest req,HttpServletResponse resp) throws IOException
	{
	    String msPhoneBookEndpt=req.getRequestURI().replace("/OPENID/msPhoneBook","");
	    switch(msPhoneBookEndpt)
	    {
	       //When user clicks on sign in with mano build the authorization requested URL
	       case "/login"     : buildAuthorizeURI(req,resp);
	                           break;
	        
	        //It is the redirected uri for the msOIDC response
	       case "/response1" : try {
				               processOIDCresp(req,resp);
			                   } catch (IOException | InterruptedException | NoSuchAlgorithmException | InvalidKeySpecException | ClassNotFoundException | SQLException e) {
				               e.printStackTrace();
			                   }
	                           break;
	         
	       //When user clicks on access more profile info it will invoked 
	       case"/userinfo"   :try {
				              getUserInfoFromOIDC(req,resp);
			                  } catch (IOException | InterruptedException e) {
				              e.printStackTrace();
			                  }
	                          break;
	    }
	}
	
	//First get the access token to access the protected resources on web API
	public static void getUserInfoFromOIDC(HttpServletRequest req,HttpServletResponse resp) throws IOException, InterruptedException
	{
		Cookie c[]=req.getCookies(); 
		String accessToken=null;
		//c.length gives the cookie count 
		for(int i=0;i<c.length;i++){  
		 if(c[i].getName().equals("access_token"))
			 accessToken=c[i].getValue();
		}
		//Send HTTP Post request to get the users profile to msOIDC userinfo endpoint
		HttpRequest IDTokKeyVerified = HttpRequest.newBuilder()
		                .uri(URI.create("http://localhost:8080/OPENID/msOIDC/userinfo"))
		                .POST(BodyPublishers.ofString(""))
		                .header("client_id","mano.lmfsktkmyj")
		                .header("scope","profile")
		                .header("access_token",accessToken)
		                .build();
		HttpClient client = HttpClient.newHttpClient();
		        // Send HTTP request
	    HttpResponse<String> tokenResponse;
		tokenResponse = client.send(IDTokKeyVerified,
	    HttpResponse.BodyHandlers.ofString());
						
		//Enclosed the response in map datastructure ,it is easy to parse the response
		Map<String,Object> validateissuer_resp=processJSON(tokenResponse.body().replace("{", "").replace("}",""));
		responseFormat(validateissuer_resp, resp);
	}
    
	//This function is used to displayed the response in proper format
	public static void responseFormat(Map<String,Object> respFormat,HttpServletResponse resp) throws IOException
	{
		 Iterator<Map.Entry<String,Object>> response = respFormat.entrySet().iterator();
            resp.getWriter().println("{");
	        while(response.hasNext())
	        {
	             Map.Entry<String, Object> entry = response.next();
	             resp.getWriter().println(entry.getKey() +":"+ entry.getValue());
	        }
	        resp.getWriter().println("}");
	}
	
	//When clicks on signin with mano this fn is called to built the AuthorizeURI
	public static void buildAuthorizeURI(HttpServletRequest req,HttpServletResponse resp) throws IOException
	{
		HttpSession session=req.getSession();
		//generate random string for the state param in authorize query
	    String state=randomStringGenerator(6);
	    
	    //generate random string for the nonce parameters in authorize query(Implicit flow/Hybrid flow)
	    String nonce=randomStringGenerator(6);
	    String response_type=authPickFlow(5);
	    //store the state value as key and response_type as value in session and cross verified the state value in response to avoid CSRF attack
	    //parallely process the future request based on response_type by passing the state parameter from the response and get the required response_type
	    session.setAttribute(state, response_type);
	    //It is on the session to verified the ID Token(Implict flow,Hybrid Flow)
	    session.setAttribute(nonce,nonce);
	  //  System.out.println(state+":"+(String) session.getAttribute(state));
	    //Build the URI with clientID,scope,state,redirectURI,response type
		String url="http://localhost:8080/OPENID/msOIDC/authorize?client_id=mano.lmfsktkmyj&scope=openid profile&state="+state+"&redirect_uri=http://localhost:8080/OPENID/msPhoneBook/response1&response_type="+response_type+"&nonce="+nonce;
		//Redirect the browser to msOIDC authorization endpoint
		resp.sendRedirect(url);
	}
	
	//It is for experiment purpose to check whether all types of flow are work.
	public static String authPickFlow(int flow_id)
	{
		String[] flowtypes= {"code","id_token","id_token token","code id_token","code token","code id_token token"};
		return flowtypes[flow_id];
	}
	
	//This function will helps to decode the ID Token such as Payload and header
	public static ArrayList<String> decodeIDTokeheadPay(String id_Token)
	{
		ArrayList<String>decodeParams=new ArrayList();
		//Split the Token as Header,Payload,Signature
		String[] splitToken = id_Token.split("\\.");
		Base64.Decoder decoder = Base64.getDecoder();
        //Decode the header and pickup the public key and verified with the issuer url by sending to it.
		String header = new String(decoder.decode(splitToken[0])).replace("{", "").replace("}","");
		String payload= new String(decoder.decode(splitToken[1])).replace("{", "").replace("}","");
		decodeParams.add(header);
		decodeParams.add(payload);
		return decodeParams;
	}
	
	//It will process the response returned from Token Endpoint of msOIDC server
	public static void processOIDCresp(HttpServletRequest req,HttpServletResponse resp) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException, SQLException
	{
		HttpSession session=req.getSession();
		//check the state parameters from the response with state parameter in the session,saved during authorization request
		String state=(String)req.getParameter("state");
		
		if(state!=null)
		{
		   //Pick up the response type associated with the state parameters
		  String response_type=(String)session.getAttribute(state);
		  if(response_type!=null)
		  {
			  if(response_type.contains("id_token"))
			  {
				//If the response type contains id_token(validate the ID Token create one cookie for authenticated users and send to user agent(browser)
				//If the response type contains id_token token(validate the ID Token create one cookie for authenticated users and send to user agent(browser) 
				//and when users needs to access more profile info using access token we can get it.
				 
				 //Decode the ID Token(headers and payload)
				ArrayList<String>decodeParams=decodeIDTokeheadPay(req.getParameter("id_token"));
				//Convert the JSON into key value pairs
			    Map<String,Object> headers=processJSON(decodeParams.get(0));
				Map<String,Object> payloads=processJSON(decodeParams.get(1));
				
				//Validate the public key by sending request to issuer(URL) by passing clientid and kid as header parameters
				if(ValidateIDissuerKey((String) payloads.get("iss"),(String) headers.get("kid"),resp))
				  {
					  //Decoded the public key from the encoded kid for signature verifications 
					  PublicKey pubkeys=pubkeyEncoder(Base64.getDecoder().decode((String) headers.get("kid")));
					  if(ValidateTokenSignature(req.getParameter("id_token"),pubkeys))
					  {
						  responseFormat(payloads,resp);
						  
						  //another flow of implicit(id_token token)
						  if(response_type.contains("token"))
						   {
							//save the token in cookie
							//Create one session for that authenticated users and redirected to Home Page
							  Cookie auth_uesr = new Cookie("access_token",req.getParameter("access_token"));
							  resp.addCookie(auth_uesr);
						   }
						   //Redirected to Home Page
						    //if(!response_type.contains("code"))
							//resp.sendRedirect("http://localhost:8080/OPENID/phoneBookHome.jsp");
					  }
					  else
					  {
						  //Signature Invalid and Token become Invalid and reauthenticate again
						  resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
					  }
				  }
				  else
				  {
					  //issuer invalid
					  resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
				  }
			  }
			 //Token Endpoint request for authorization code Flow
		    /* if(response_type.contains("code"))
		     {
		    	 authCodeProcessModel authModel=new authCodeProcessModel();
		    	 authModel.setClientid("mano.lmfsktkmyj");
		    	 authModel.setClientsecret("mano.tpeoeothyc");
		    	 authModel.setCode((String)req.getParameter("code"));
		    	 authModel.setRedirecturi("http://localhost:8080/OPENID/msPhoneBook/response1");
		    	 
		    	 //Get response from the token endpoint
		    	 Map<String,Object> tokenResp=authCodeProcess(authModel,resp);
		    	 //Check if the response returned any error
		    	 if(tokenResp.containsKey("error"))
		    	 {
		    	     //Token response made error redirected to signin with mano page again
		    		 resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
		    	 }
		    	 else
		    	 {
		    		 responseFormat(tokenResp,resp);
		    		 //Validate ID Token
		    		 ArrayList<String>decodeParams=decodeIDTokeheadPay((String) tokenResp.get("id_token"));
						//Convert the JSON into key value pairs
					 Map<String,Object> headers=processJSON(decodeParams.get(0));
					 Map<String,Object> payloads=processJSON(decodeParams.get(1));
					 
					//Validate the public key by sending request to issuer(URL) by passing clientid and kid as header parameters
					 if(ValidateIDissuerKey((String) payloads.get("iss"),(String) headers.get("kid"),resp))
					  {
						  //true check signature
						  PublicKey pubkeys=pubkeyEncoder(Base64.getDecoder().decode((String) headers.get("kid")));
						  //Validate the signature using public key
						  if(ValidateTokenSignature((String) tokenResp.get("id_token"),pubkeys))
						  {
							  //Valid the access token with the at_hash values in the ID Token
							  //First hash the access token and compared with at_hash value in the ID Token
							  if(payloads.get("at_hash").equals(hashPass((String)tokenResp.get("access_token"))))
							  {
								  //save access token along with refresh token to client database used when acces token get expired
								 PhoneBookDAO.saveTokens((String)tokenResp.get("access_token"),(String)tokenResp.get("refresh_token"));
								 
								//Create one cookie for that authenticated users and redirected to Home Page and send cookie to browser
								 session.setAttribute("enduser_name",payloads.get("sub"));
								 Cookie auth_uesr = new Cookie("access_token",(String) tokenResp.get("access_token"));
								 resp.addCookie(auth_uesr);
								 //Redirected to Home Page
							     resp.sendRedirect("http://localhost:8080/OPENID/phoneBookHome.jsp");
							  }
							  else
							  {
								  //Invalid Access Token(Reauthenticate again)
								  resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
							  }  
						  }
						  else
						  {
							  //Signature invalid
							  resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
						  }
		    	        }
			           else
			          {
				        //Invalid issuers or public key(reauthenticate again)
				        resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
			          }
		           }
		         }*/
		    }
		   else
		   {
			//If the state value is not matched with the state value generated during authorization request CSRF attack
			//sign up again
			   resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
		   }
		}
		else
		{
			//state missing from server,response may be from unknown server,so sign up again
			resp.sendRedirect("http://localhost:8080/OPENID/PhoneBookLogin.jsp");
		}
	}
	
	 // verify the ID Token using public key
    private static boolean ValidateTokenSignature(String token, PublicKey publicKey) {
    	boolean verified=true;
        try {
        	Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
        } catch (Exception e) {
                verified=false;
        }
        return verified;
    }
    
    //Get the public key by passing the public key
    public static PublicKey pubkeyEncoder(byte[] pubkey) throws NoSuchAlgorithmException, InvalidKeySpecException
	   {
		X509EncodedKeySpec  encode_pub_key = new X509EncodedKeySpec(pubkey);
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");	  
	    PublicKey publickey = keyFactory.generatePublic(encode_pub_key);
	    return publickey;
	   }
	
    //Validate the issuer claims and kid in the header
	public static boolean ValidateIDissuerKey(String issuer,String kid,HttpServletResponse resp) throws IOException, InterruptedException
	{
		String IDTokURL=issuer;
		String publickey=kid;
		
		//First Validate the issuer and verifed the kid(public key) in that issuer URL
		HttpRequest IDTokKeyVerified = HttpRequest.newBuilder()
                .uri(URI.create(IDTokURL))
                .POST(BodyPublishers.ofString(""))
                .header("client_id","mano.lmfsktkmyj")
                .header("public_key",publickey)
                .header("Content-Type", "application/json")
                .build();
		HttpClient client = HttpClient.newHttpClient();
        // Send HTTP request
			HttpResponse<String> tokenResponse;
				tokenResponse = client.send(IDTokKeyVerified,
				        HttpResponse.BodyHandlers.ofString());
				
		//Enclosed the response in map datastructure ,it is easy to parse the response
		Map<String,Object> validateissuer_resp=processJSON(tokenResponse.body().replace("{", "").replace("}",""));
		if(validateissuer_resp.get("verified").equals("true"))
		return true;
		else
		return false;
	}
	
	//Process the JSON string returns the value in key value pairs which heps for further processing
	public static Map<String,Object> processJSON(String jsontoMap)
	{
		String[] splitkeyval=null;
		Map<String,Object> mapConvert=new HashMap();
		String[] splitjson=jsontoMap.replace("\"","").split(",");
		for(int i=0;i<splitjson.length;i++)
		{
			if(splitjson[i].contains("iss"))
			{
				int col=splitjson[i].indexOf(":");
				splitjson[i] = splitjson[i].substring(0,col) +"="
			              + splitjson[i].substring(col + 1);
				splitkeyval=splitjson[i].split("=");
			}
			else
			{
			   splitkeyval=splitjson[i].split(":");
			}
			mapConvert.put(splitkeyval[0], splitkeyval[1]);
		}
		return mapConvert;
	}
	//Create a map based datastructure for the response returned from msOIDC server
	public static Map<String,Object> authCodeProcess(authCodeProcessModel authVal,HttpServletResponse resp) throws IOException, InterruptedException
	{
        // Concatenate clientid and clientsecret and use base64 to encode the concatenated string for security purpose to authenticate the client
        String clientandSecret = authVal.getClientid() + ":" + authVal.getClientsecret();
        //encoding the clientid with client secret
        String base64ClientandSecret = new String(Base64.getEncoder().encode(clientandSecret.getBytes()));
        
        //Create http client for request to token endpoint for get access token and refresh token 
        HttpClient client = HttpClient.newHttpClient();

        // Create HTTP POST request object for Token Request
        HttpRequest tokRequest = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:8080/OPENID/msOIDC/token"))
                .POST(BodyPublishers.ofString(""))
                .header("Authorization",base64ClientandSecret)
                .header("grant_type", "authorization_code")
                .header("redirect_uri",authVal.getRedirecturi())
                 .header("code", authVal.getCode())
                .header("Content-Type", "application/json")
                .build();
        // Send HTTP request
			HttpResponse<String> tokenResponse;
				tokenResponse = client.send(tokRequest,
				        HttpResponse.BodyHandlers.ofString());
	    //Enclosed the response in map datastructure ,it is easy to parse the response
	    Map<String,Object> tokenResp=processJSON(tokenResponse.body().replace("{", "").replace("}",""));
	    return tokenResp;
	}
	//Random String Generator for state param in authorization request to avoid CSRF attack
    public static String randomStringGenerator(int len)
    {
   	    int lLimit = 97; 
   	    int rLimit = 122; 
   	    int targetStringLength =len;
   	    Random random = new Random();
           String generatedString = random.ints(lLimit, rLimit + 1)
   	      .limit(targetStringLength)
   	      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
   	      .toString();
           return generatedString;
    }
    //It is used the hash the clientid with secret and accesstoken using MD5 Hashing algo
    public static String hashPass(String value) throws NoSuchAlgorithmException
	{
		//There are many algos are available for hashing i)MD5(message digest) ii)SHA(Secured hash algo)
		MessageDigest md=MessageDigest.getInstance("MD5");
	    md.update(value.getBytes());
	   
	    byte[] hashedpass=md.digest();
	    StringBuilder hashpass=new StringBuilder();
	    for(byte b:hashedpass)
	    {
	    	//Convert to hexadecimal format
	        hashpass.append(String.format("%02x",b));
	    }
	    return hashpass.toString();
	}
}
