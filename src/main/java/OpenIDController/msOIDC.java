package OpenIDController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.gson.JsonObject;
import OpenIDDAO.OpenIdDao;
import OpenIDDAO.ResourceAPIDao;
import OpenIDModel.AccessTokenModel;
import OpenIDModel.CreateAccModel;
import OpenIDModel.DeveloperModel;
import OpenIDModel.RefreshTokenModel;
import OpenIDModel.SaveAuthParamModel;
import OpenIDModel.grantCodeModel;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class msOIDC extends HttpServlet
{
	protected void service(HttpServletRequest req,HttpServletResponse resp) throws IOException
	{
	    String msOIDCServerEndpt=req.getRequestURI().replace("/OPENID/msOIDC","");
	    
	    switch(msOIDCServerEndpt)
	    {
	       //It will gets invoked when they requested for developer console home page
	      case "/msdeveloper"            :devRedirect(req,resp);
	                                      break;
	                                  
	          //When user logs in their mano's accounts on server this case will called
                                      
          case "/msaccounts/login"       :try {
				                          LogVerified(req,resp);} catch (ClassNotFoundException | SQLException | IOException | NoSuchAlgorithmException e) {
				                          e.printStackTrace();}
                                          break;
	      
	      //When user create an account on mano accounts server this case will called
                                 
         case "/msaccounts/createAcc"    :try {
				                          createAcc(req,resp);} catch (ClassNotFoundException | SQLException | NoSuchAlgorithmException e) {
				                          e.printStackTrace();}
                                          break;
                                         
               //Developer console endpoint to registered the client
         case "/msdev/newClient"         :try {
		                                  uploadDevDetails(req,resp);
	                                      } catch (ClassNotFoundException | IOException | SQLException | NoSuchAlgorithmException e) {
		                                  e.printStackTrace();}
                                          break;
                                      
               //It will gets invoked and clear all session belongs to that developer
         case "/developer/logout"        :devLogOut(req,resp);
                                          break;
         
                 //Initial endpoint for authorization request
         case "/authorize"               :saveReqParam(req,resp);
                                          break;
         
            //This endpoint will gets called when verified the client and scope parameters
         case "/verifyClientAndScope"    :try {
				                          verifyClientAndScope(req,resp);} catch (ClassNotFoundException | SQLException e) {
				                          e.printStackTrace();}
                                          break;
                                          
           //When the resource owner grants permission for the resources this case will called                          
         case "/codeortoksent"           :try {
			                              issueCodeIdTokSent(req,resp);}catch (ClassNotFoundException | SQLException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			                              e.printStackTrace();}
                                          break;
                                                   
      //When the resource owner denied the permission grants for the requested resources this case will called 
         case "/grantdenied"             :deniedAuthorizationGrant(req,resp);
                                          break;
                                                   
        //Endpoint for Code Exchange for accesstoken, Refresh Token,ID Token(token Endpoints)
         case "/token"                   :try {
        	                              issueAccRefIDToken(req,resp);} catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException | IOException| SQLException | ParseException e) {
				                          e.printStackTrace();}  
                                          break;
                                          
         //It returns the public key associated with requested clientid(URL request from the client during verification of kid value in header in ID Token)
         case "/validIDTok/publickey"    :try {
				                          verifyValidPubKey(req,resp);} catch (ClassNotFoundException | SQLException | IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				                          e.printStackTrace();}
                                          break;
                                          
            //Userinfo endpoint to get the info about the user and returned to the client
         case "/userinfo"                 : try {getUserProfileDetails(req,resp);} catch (NumberFormatException | ClassNotFoundException | SQLException | ParseException | IOException e) {
			                                e.printStackTrace();}
                                            break;
	    }
	   
	}
	
      //When developer requested for creating one new clients
      void devRedirect(HttpServletRequest req,HttpServletResponse resp) throws IOException
	   {
		   //Create one session this login is to verified the developers
		   HttpSession dev_verified_session=req.getSession();
		   dev_verified_session.setAttribute("dev_login","1");
		   resp.sendRedirect("http://localhost:8080/OPENID/ManoLogin.jsp");
	   }
	   
	   //Verified the Login Credentials(email,password)
	   void LogVerified(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, NoSuchAlgorithmException, SQLException, IOException
	   {
		   HttpSession log_verify_session=req.getSession();
		   deleteSessionValues(req,"invalid_login");
		   String email=req.getParameter("logmail");
	 	   String password=req.getParameter("logpass");
		   ArrayList<Object> log_user_details=OpenIdDao.checkUser(email,password);
		   
		   //In log_user_details --->0th index contains uid and 1st index contains name of the authenticated users
		   //name is used in developerHome to mentioned the name of the developer as well as it helps in authorization consent window
		   log_verify_session.setAttribute("log_user_details",log_user_details);
		   if((int)log_user_details.get(0)!=0)
		   {
			   if(log_verify_session.getAttribute("dev_login")!=null)
			   { 
				//If this login verified intended for verified the developer credentials then after verified navigate to developer home
			    resp.sendRedirect("http://localhost:8080/OPENID/developerHome.jsp"); 
			   }
			   else
			   {
				   //For authorization flow
				   resp.sendRedirect("http://localhost:8080/OPENID/msOIDC/verifyClientAndScope"); 
			   }
		   }
		   else
		   {
			   //If login credentials are not valid
			   log_verify_session.setAttribute("invalid_login","1");
			   resp.sendRedirect("http://localhost:8080/OPENID/ManoLogin.jsp");
		   }
		   
	   }
	   
	    //When end users clicks on create a brand new account
		void createAcc(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException, NoSuchAlgorithmException
	    {
	 	   String refreshTokens="";
	 	   //Create one object in CreateAccModel and stored the value into it
	 	   
	 	   CreateAccModel newuser=new CreateAccModel();
	 	   newuser.setName(req.getParameter("crename"));
	 	   newuser.setEmail(req.getParameter("cremail"));
	 	   newuser.setPassword(req.getParameter("crepass"));
	 	   newuser.setLocation(req.getParameter("creloc"));
	 	   newuser.setPhone(req.getParameter("cremobile"));
	 	   
	 	 //Generate 20 refresh token for per accounts which helps during refreshing the access tokens.
	 	   for(int i=1;i<=20;i++)
	 	   {
	 		   //Each tokens will seperated by commas.
	 		   refreshTokens=refreshTokens.concat(randomStringGenerator());
	 		   if(i<20)
	 		   {
	 			   refreshTokens=refreshTokens.concat(",");  
	 		   }
	 	   }
	 	   
	 	   //Stored the new users details in users table and 20 refreshTokens in refTokenHolder table
	 	   OpenIdDao.InsertUser(newuser, refreshTokens);
	 	   resp.sendRedirect("http://localhost:8080/OPENID/ManoLogin.jsp");
	    }
		
		//Upload the developer details to developerdb
		void uploadDevDetails(HttpServletRequest req,HttpServletResponse resp) throws IOException, ClassNotFoundException, SQLException, NoSuchAlgorithmException
	    {
		   HttpSession session=req.getSession();
		   //create one developer model obj for combined the developer details
	       DeveloperModel newdev=new DeveloperModel();
	       
	       newdev.setUid((int)((ArrayList<Object>)session.getAttribute("log_user_details")).get(0));
	       newdev.setClientId((String) session.getAttribute("clientID"));
	       newdev.setClientSecret((String) session.getAttribute("clientSecret"));
	       newdev.setAppName(req.getParameter("appname"));
	       newdev.setRedirectUri(req.getParameter("url1"));
	       
	        //Generate RSA Key pair
	        Map<String, Object> rsaKeys = null;
	        rsaKeys = generateRsaKeys();
	        PublicKey publicKey = (PublicKey) rsaKeys.get("public");
	        PrivateKey privateKey = (PrivateKey) rsaKeys.get("private");
	        
	        //encoded for security purpose 
	        byte[] public_key_bytes = publicKey.getEncoded();
	        byte[] private_key_bytes = privateKey.getEncoded();
	        
	       //Store public key in developerdb table used when validate the ID token(JWT)
	       newdev.setRsaPubKey(public_key_bytes);
	       
	      // Store private key in developerdb table used when create the ID token(JWT)
	       newdev.setRsaPrivateKey(private_key_bytes);
	       
	       //Here we have concatenate the multiple redirected uri's and each seperated by commas.
	       //When validate the redirected uris we split up based on commas and stored in arrayList and validation made easier.

	       if((req.getParameter("url2").contains("null"))==false)
	       {
	         //Concatenate with URL 1 each of us seperated by commas
	         newdev.setRedirectUri(newdev.getRedirectUri().concat(','+req.getParameter("url2")));
	       }
	       if((req.getParameter("url3").contains("null"))==false)
	       {
	         //Concatenate with URL 1,2 each of us seperated by commas
	         newdev.setRedirectUri(newdev.getRedirectUri().concat(','+req.getParameter("url3")));
	       }
	       
	       //Uploaded the details to developerdb table in database.
	       OpenIdDao.InsertDeveloper(newdev);
	       //After successful saved the developer credentials delete the clientID and Client secret sessions
	       deleteSessionValues(req,"clientID");
	       deleteSessionValues(req,"clientSecret");
	       //Redirect to developer Home page
	       resp.sendRedirect("http://localhost:8080/OPENID/developerHome.jsp"); 
	    }
		
		//When developer clicks on logout delete the session associated with it
		public static void devLogOut(HttpServletRequest req,HttpServletResponse resp) throws IOException
		{
			//delete the developer logout session and redirected to login page
			deleteSessionValues(req,"log_user_details");
			deleteSessionValues(req,"dev_login");
			resp.sendRedirect("http://localhost:8080/OPENID/ManoLogin.jsp");
		}
		
		//First saved the queryParameters for authorization and redirected to Login Page for authentication
		public static void saveReqParam(HttpServletRequest req,HttpServletResponse resp) throws IOException
		{
			  String[] flowtypes= {"code","id_token","id_token token","code id_token","code token","code id_token token"};
			  HttpSession session=req.getSession();
	          //Get query params
			  String response_type=req.getParameter("response_type");
			  String client_id=req.getParameter("client_id");
			  String scope=req.getParameter("scope");
		      String redirect_uri=req.getParameter("redirect_uri");
	          String state=req.getParameter("state");
	          
	          //Check whether the response type is valid or not
	          boolean response_type_status=checkValidResponseType(response_type);
	          
	          //Check whether all the parameters are present and response type is valid 
	          if((response_type!=null &&response_type_status) && client_id!=null &&scope!=null &&redirect_uri!=null&&state!=null)
	          {
	          //Create one SaveAuthParamModel object to store the query parameter
	          SaveAuthParamModel queryParam=new SaveAuthParamModel();
	          queryParam.setResponseType(response_type);
	          queryParam.setClientId(client_id);
	          queryParam.setScope(scope);
	          queryParam.setRedirectUri(redirect_uri);
	          queryParam.setState(state);
	          
	          //if authorization flow is implicit or hybrid nonce parameter is mandatory
	          if(queryParam.getResponseType().equals("code")==false)
	          {
	       	       queryParam.setNonce(req.getParameter("nonce"));
	          }
	          if(!response_type_status)
	           {
	        		  //if none of the below response type will gets matched returns unsupported response type error codes
	        		  authErrorCodes(3,redirect_uri,state,resp);
	           }
	           else if(queryParam.getNonce()==null &&queryParam.getResponseType().equals("code")==false)
	           {
	        	    //When the request is missing a required parameter,nonce it returns error
		         	 authErrorCodes(0,redirect_uri,state,resp); 
	           }
	           else
	           {
	          
	          //Create one session for this query param, for this authorization request 
	          session.setAttribute("saveAuthParam", queryParam);
	          
	          //Redirected to Authentication Page(Login Page)
	           resp.sendRedirect("http://localhost:8080/OPENID/ManoLogin.jsp");
	          }
	          }
	          else
	          {
	        	//When the request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once
	         	 authErrorCodes(0,redirect_uri,state,resp);
	          }
		}
		
		//To check valid whether it is a valid response type in queryParam in authorization request
		public static boolean checkValidResponseType(String response_type)
		{
			ArrayList<String> flowtypes= new ArrayList<String>(Arrays.asList("code","id_token","id_token token","code id_token","code token","code id_token token"));
			return flowtypes.contains(response_type);	
		}
		
		//Verified the client(clientid,redirecturi) then verified the requested scope in queryParam
		public static void verifyClientAndScope(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException
		{
			HttpSession session=req.getSession();
			
			//Get the uid from the session when we stored after the successful authentication
			int uid=(int)((ArrayList<Object>)session.getAttribute("log_user_details")).get(0);
		 	SaveAuthParamModel queryValue=(SaveAuthParamModel)session.getAttribute("saveAuthParam");
		 	
		 	//Extract the exact scope parameters
			queryValue.setScope(queryValue.getScope().replace("openid ", "").replace(" ",","));
			
			//Check the Client Credentials
			Map<String,Object>clientCredentials=OpenIdDao.verifyDeveloper(queryValue.getClientId(),0);
			
			//Create one session for client credentials used for display appname in authorization consent.
			//generate ID token to the client using RSA keys after successful authorization by end users
			session.setAttribute("client_credentials", clientCredentials);
			
			if(!clientCredentials.isEmpty())
			{
				//Verified the redirected uris with what the developer given during client registration
				String splitted_redirect_URIS=(String)clientCredentials.get("redirecturis");
				
				//Split the redirected uris for comparision
				ArrayList<String> split_redirectUris=new ArrayList(List.of(splitted_redirect_URIS.split(",")));
				//Valid the redirected uris
				if(split_redirectUris.contains(queryValue.getRedirectUri()))
				{
					//Verified the scope whether it is valid or not in USERS API INDEX Table
					if(OpenIdDao.checkScope(uid,queryValue.getScope()))
					{
						resp.sendRedirect("http://localhost:8080/OPENID/ResourceConfirm.jsp");
					}
					else
					{
						 //returned the error as invalid scope to the client
						 authErrorCodes(4,queryValue.getRedirectUri(),queryValue.getState(),resp); 
					}
				}
				else
				{
					//redirectURI is not match with URIS given during registered the Client
					session.setAttribute("error","Invalid Redirected URI");
					resp.sendRedirect("http://localhost:8080/OPENID/ErrorPage.jsp");
				}
			}
			else
			{
				//Invalid client or Unauthorized Client error response
				 authErrorCodes(1,queryValue.getRedirectUri(),queryValue.getState(),resp); 
			}
			
		}
		
		//Function for the Authorization endpoint
	    public static void issueCodeIdTokSent(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
	    {
	      //Create one map for holding claims for ID Token
	      Map<String,Object> id_claims = new HashMap<String,Object>();
	      
	  	  //Here response will depends on the type of flow,
	  	  HttpSession session=req.getSession();      
	  	  SaveAuthParamModel queryValue=(SaveAuthParamModel)session.getAttribute("saveAuthParam");
	  	  int uid=(int)((ArrayList<Object>)session.getAttribute("log_user_details")).get(0);
	  	  
	  	  //This string variable will built the redirect uri parameters based on response_type
	  	  String redirect_uri=queryValue.getRedirectUri()+"?";
	  	  
	  	  //Get the username for that uid which is the subject identifier claim values for the ID tokens
	  	  String username=(String)((ArrayList)session.getAttribute("log_user_details")).get(1);
	  	  
	  	  //Split the response_type based on " " 
	  	  String[] response_splits=queryValue.getResponseType().split(" ");
	  	  for(int i=response_splits.length-1;i>=0;i--)
	  	  {
	  		  switch(response_splits[i])
	  		  {
	  		     case "code"     ://Create one object for the grantcode and insert the values
	  				             grantCodeModel newGrantCode=new grantCodeModel(queryValue.getClientId(),randomStringGenerator(),timeGenerator(2),queryValue.getScope(),uid,1);
	  				             
	  				             //insert the grantCode object to the grantcodelog table
	  				             OpenIdDao.saveGrantCode(newGrantCode);
	  				             
	  				            //Create one session for nonce param with respect to state value which helps to insert it as a claims in ID Token(Implicit flow/Hybrid Flow)
	  			        	    //For validate the token in client side
	  			        	    session.setAttribute(newGrantCode.getGrantCode(), queryValue.getNonce());
	  				            //It will append the auth code along with redirected uri's
	  						     redirect_uri+="code="+newGrantCode.getGrantCode()+"&";
	  				             break;
	  			
	  				              //Upload the required claims to be present in the ID Token
	  		     case "id_token" :id_claims.put("uid",uid);id_claims.put("sub",username);id_claims.put("aud",queryValue.getClientId());id_claims.put("nonce",queryValue.getNonce());id_claims.put("iss","http://localhost:8080/OPENID/msOIDC/validIDTok/publickey");
	  		     
	  		    	              //get private keys and public key for generate ID Token(JWT)
	  			  	              byte[] private_key= (byte[])((Map<String,Object>)session.getAttribute("client_credentials")).get("rsaprivatekey");
	  			  	              byte[] public_key= (byte[])((Map<String,Object>)session.getAttribute("client_credentials")).get("rsapubkey");
	  			                  
	  			  	              //We need claims values such as uid,subject identifier(username),audience as (clientId)
	  				              String jwtToken=createJWTToken(id_claims,private_key,public_key);
	  				              
	  				              //Append ID token along with redirect_uri
	  				              redirect_uri+="id_token="+jwtToken+"&";
	  				              break;
	  				              
	  		     case "token"    ://Generate access token from the authorization endpoint for implicit flow
	  				              String newAccToken=reuseAccessTokenCode(req, uid,queryValue.getClientId(),queryValue.getScope());
	  				              //hash the access token which is returned to the client,which is used for validation the access token in client side
	  				              id_claims.put("at_hash",OpenIdDao.hashPass(newAccToken));
	  				              redirect_uri+="access_token="+newAccToken+"&token_type=bearer"+"&expires_in=3600&";
	  				              break;
	  		  }
	  	  }
	  	      //Saved the state parameters along with clientID to avoid CSRF attack
	  	      OpenIdDao.saveStateParam(queryValue.getClientId(),queryValue.getState());
	  	      
	  	      //Released or delete the unwanted sessions because required values are in database 
	  	      deleteSessionValues(req, "saveAuthParam");
	    	  deleteSessionValues(req, "log_user_details");
	    	  deleteSessionValues(req, "client_credentials");
	  		  //send the authorization response to the client
	  		  resp.sendRedirect(redirect_uri+"state="+queryValue.getState());
	    }
		
		//When the authorization grants was denied by the end users(Resource owners)
	    public static void deniedAuthorizationGrant(HttpServletRequest req,HttpServletResponse resp) throws IOException
	    {
	    	HttpSession session=req.getSession();
	    	SaveAuthParamModel queryValue=(SaveAuthParamModel)session.getAttribute("saveAuthParam");
	    	String redirect_uri=queryValue.getRedirectUri();
	    	String state=queryValue.getState();
	    	//Released or delete session after resource permission denied
	    	deleteSessionValues(req, "saveAuthParam");
	    	deleteSessionValues(req, "log_user_details");
	    	deleteSessionValues(req, "client_credentials");
	    	authErrorCodes(2,redirect_uri,state, resp);
	    }
		//Returns the possible exceptions or error codes when validating the query parameters involved in the authorization and authentication request
	    public static void authErrorCodes(int error_no,String redirecturi,String state,HttpServletResponse resp) throws IOException
	    {
	    	String[] auth_error_code= {"invalid_request","unauthorized_client","access_denied","unsupported_response_type","invalid_scope","server_error","temporary_unavailable"};
	    	resp.sendRedirect(redirecturi+"?error="+auth_error_code[error_no]+"&state="+state);
	    }
	    
	    //Token Endpoints
	    public static void issueAccRefIDToken(HttpServletRequest req,HttpServletResponse resp) throws IOException, ClassNotFoundException, SQLException, ParseException, NoSuchAlgorithmException, InvalidKeySpecException
	    {
	    	HttpSession session=req.getSession();
	      HashMap<String,Object> jsonresp=new HashMap<String,Object>();
	      
          //Get the encoded clientid with client secret
	  	  String clientcredentials=req.getHeader("Authorization");
	  	  
	  	  //Decoded the base64client credentials
	  	  byte[] clientDecoded = Base64.getDecoder().decode(clientcredentials);
          String[] splitCredentials = (new String(clientDecoded, StandardCharsets.UTF_8)).split(":");
          
          //Seperate the clientid and client secret
          String clientid=splitCredentials[0];
          String clientsecret=splitCredentials[1];
          
	      String grant_type=req.getHeader("grant_type");
	      String redirect_uri=req.getHeader("redirect_uri");
	      String auth_code=req.getHeader("code");
	      String refresh_token="";
	      
	      //First Check the grant type
	      if(grant_type.contentEquals("authorization_code")==true)
	      {
	    	   //Check for verified Client ID and Redirect URI
				Map<String,Object>clientCredentials=OpenIdDao.verifyDeveloper(clientid+","+clientsecret,1);
				
				//get private keys and public key for generate ID Token(JWT)
  	            byte[] private_key= (byte[])clientCredentials.get("rsaprivatekey");
  	            byte[] public_key= (byte[])clientCredentials.get("rsapubkey");
  	              
		       if(!clientCredentials.isEmpty())
	           {
		    	 //Check whether the grantcode is valid or not and whether we need to issued refresh token along access token or not
	         	  
	         	  //The below function returned two values one is uid of the user.Next status of refresh token issued 
	         	   //0--->Not issued refresh token along with access token,1---->issued refresh token along with access token
	         	  
	         	  ArrayList<Object> refreshissued=OpenIdDao.validateGrandCode(auth_code);
	         	  
	         	  //Check if the grandcode is valid or not
	         	  if(refreshissued.get(0)!=null)
	         	  {
	         		//Get the username for that uids which is the subject identifier claim values for the ID tokens
	         	  	String username=OpenIdDao.getUserName((Integer)refreshissued.get(0));
	         	  	
	         	 //Create one map for holding claims for ID Token
	      	       Map<String,Object> id_claims = new HashMap<String,Object>();
	      	      
	      	       id_claims.put("uid",refreshissued.get(0));id_claims.put("sub",username);id_claims.put("aud",clientid);id_claims.put("iss","http://localhost:8080/OPENID/msOIDC/validIDTok/publickey");
	      	       
	      	       //if it is hybrid flow,then nonce parameter needs to included in ID Token claims
	      	        if(session.getAttribute(auth_code)!=null)
	      	        id_claims.put("nonce",session.getAttribute(auth_code));
	      	        
	         		//No refresh token issued if refresh_issued status==0
	         		String access_token=reuseAccessTokenCode(req,(Integer)refreshissued.get(0), clientid,(String)refreshissued.get(2));
	         		
	         		//hash the access token which is returned to the client,which is used for validation the access token in client side
		            id_claims.put("at_hash",OpenIdDao.hashPass(access_token));
		            
	         		 //We need claims values such as uid,subject identifier(username),audience as (clientId)
	         		String jwtToken=createJWTToken(id_claims,private_key,public_key);
	         		
	         		// issued refresh token along with access token if refresh_issued status==1
	         		if((Integer)refreshissued.get(1)==1)
	         		{
	         		     refresh_token=reuseRefreshTokenCode(req,(Integer)refreshissued.get(0), clientid,(String)refreshissued.get(2));
	         		}
	         		    // made required key value pairs into the Hashmap which helps to built JSON response .
	         		    jsonresp.put("access_token",access_token);
	         		    jsonresp.put("token_type", "Bearer");
	         		    if(refresh_token.isEmpty()==false)
	         		    jsonresp.put("refresh_token",refresh_token);
	        		    
	         		    jsonresp.put("expires_in",3600);
	         		    jsonresp.put("id_token",jwtToken);
	         	  }
	         	  else
	         	  {
	         		  //Invalid grant code(may it can expired or not avail)
	         		  jsonresp.put("error", "unsupported_grant_type");
	         	  }
	           }
		       else
		       {
		    	   //invalid clientId and redirecturi
		    	   jsonresp.put("error", "unauthorized_client");
		       }
	      }
	      else
	      {
	    	  //invalid grant code in request param
	    	  jsonresp.put("error", "invalid_grant");
	      }
	      
	      //built JSON token response
	      builtJSON(jsonresp, req, resp);
	  	  }
	    
	    //Built JSON Format for token response to client
	   public static void builtJSON(HashMap<String,Object> jsonresp,HttpServletRequest req,HttpServletResponse resp) throws IOException
	    {
	    	HttpSession session=req.getSession();
	    	resp.setContentType("application/json");
	 		resp.setCharacterEncoding("utf-8");
	 		
	 		//create Json Object to return token response
	 		JsonObject json = new JsonObject();
	    	for(String key:jsonresp.keySet())
	    	{
	    		if(key.contentEquals("expires_in")==true)
	    		{
	    		json.addProperty(key,(Integer)jsonresp.get(key));
	    		}
	    		else
	    		{
	    		json.addProperty(key,(String)jsonresp.get(key));
	    		}
	    	}
	    	// finally return the json response to client     
			resp.getWriter().print(json.toString());
			resp.getWriter().flush();
	    }
	   
	   //Verfied the public key for that respective clientid
	   //If its true returned verified:true
	   //else verified : false
	   public static void verifyValidPubKey(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException, NoSuchAlgorithmException, InvalidKeySpecException
	   {
		    String clientid=req.getHeader("client_id");
		    String client_pub_key=req.getHeader("public_key");
		   
		    //Get public key for that Client ID and verified with pub_key in request header
			Map<String,Object>clientCredentials=OpenIdDao.verifyDeveloper(clientid,0);
			byte[] dev_public_key= (byte[])clientCredentials.get("rsapubkey");
			if(pubkeyEncoder(dev_public_key).equals(pubkeyEncoder(Base64.getDecoder().decode(client_pub_key))))
				resp.getWriter().print("{verified:true}");
			else
				resp.getWriter().print("{verified:false}");
	   }
	     //UserInfo EndPoints
	    public static void getUserProfileDetails(HttpServletRequest req,HttpServletResponse resp) throws NumberFormatException, SQLException, ParseException, ClassNotFoundException, IOException
	    {
	    	HashMap<String,Object> jsonresp=new HashMap<String,Object>();
	    	  String clientId=req.getHeader("client_id");
	          String accesstoken=req.getHeader("access_token");
	          String scope=req.getHeader("scope");
	       if(clientId!=null && accesstoken!=null && scope!=null)
	       {
	 	     //Validate the client credentials
	    	Map<String,Object>clientCredentials=OpenIdDao.verifyDeveloper(clientId,0);
	    	if(!clientCredentials.isEmpty())
	    	{
	    		//Validate access token issued with Authorized server
	    		//Fetch the uids for that respective access Token
	          int uids=OpenIdDao.ValidateAccessToken(accesstoken,clientId,scope);
	 	     if(uids!=0)
	 	     {
	 		   //Made an API call to fetch users info
	 		   CreateAccModel usersinfo=ResourceAPIDao.getUsers(uids);
	 		   
	 		   //Built the json response about userinfo to the client
	 		  jsonresp.put("name",usersinfo.getName());
			  jsonresp.put("email",usersinfo.getEmail());
			  jsonresp.put("mobileno",usersinfo.getPhone());
			  jsonresp.put("location",usersinfo.getLocation());
			  
	 	     }
	 	     else
	 	    	//When the access token was expired or invalid
	     		jsonresp.put("error", "invalid_token");
	    	}
	    	else
	    	{
	    		//invalid clientid or redirecturi this error response will returned
	    		jsonresp.put("error", "unauthorized_client");
	    	}
	    	builtJSON(jsonresp, req, resp);
	    	}
	       else
	    	{
	    		//when there is any missing parameters in that request returns the following error response
	      		jsonresp.put("error", "invalid_request");
	      		builtJSON(jsonresp, req, resp);
	    	}
	    }
	   
	   //Public encoder required when the client request for validating the kid
	   public static PublicKey pubkeyEncoder(byte[] pubkey) throws NoSuchAlgorithmException, InvalidKeySpecException
	   {
		X509EncodedKeySpec  encode_pub_key = new X509EncodedKeySpec(pubkey);
   	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");	  
   	    PublicKey publickey = keyFactory.generatePublic(encode_pub_key);
   	    return publickey;
	   }
	  //Many flows use accessToken frequently,Made a reusability functionality for AcessToken Upload
	    public static String reuseAccessTokenCode(HttpServletRequest req,int uid,String clientId,String allScopes) throws ClassNotFoundException, SQLException
	    {
	    	HttpSession session=req.getSession();
	    	AccessTokenModel newAccToken=new AccessTokenModel(uid,clientId,randomStringGenerator(),allScopes,timeGenerator(60));
	    	//Save the access tokens
		    OpenIdDao.saveAccessTokens(newAccToken);
		    return newAccToken.getAccessToken();
	    }
	    
	    //Many flows use RefreshToken frequently,Made a reusability functionality for RefreshToken Upload
	    public static String reuseRefreshTokenCode(HttpServletRequest req,int uid,String clientId,String allScopes) throws ClassNotFoundException, SQLException
	    {
	    	RefreshTokenModel newRefToken=new RefreshTokenModel(uid,-1,clientId,"",allScopes);
	    	
	    	//Saved the access tokens and refresh tokens
	    	RefreshTokenModel refreshToken=OpenIdDao.saveRefreshToken(newRefToken);
			
			//When refresh token objects received saved the refresh tokens to issuedRefreshToken table
			OpenIdDao.saveRefreshTokens(newRefToken);
			return refreshToken.getRefreshToken();
	    }
	    
		//Random String Generator for tokens and client secret and id
	    public static String randomStringGenerator()
	    {
	   	    int lLimit = 97; 
	   	    int rLimit = 122; 
	   	    int targetStringLength =10;
	   	    Random random = new Random();
	           String generatedString = random.ints(lLimit, rLimit + 1)
	   	      .limit(targetStringLength)
	   	      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
	   	      .toString();
	           return "mano."+generatedString;
	    }
	    
	    //Generate RSA Keys for new Clients Registration which helps to send ID token to client
	    public static Map<String, Object> generateRsaKeys() throws NoSuchAlgorithmException
	    {
	    	 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	         keyPairGenerator.initialize(2048);
	         KeyPair keyPair = keyPairGenerator.generateKeyPair();
	         PrivateKey privateKey = keyPair.getPrivate();
	         PublicKey publicKey = keyPair.getPublic();
	         Map<String, Object> keys = new HashMap<String, Object>();
	         keys.put("private", privateKey);
	         keys.put("public", publicKey);
	         return keys;
	    }
	  //Create JWT Token which tells about the authentication event and short info about the end user
	    public static String createJWTToken(Map<String,Object> id_claims,byte[] private_key,byte[] pub_key) throws ClassNotFoundException, SQLException, NoSuchAlgorithmException, InvalidKeySpecException
	    {
	    	System.out.print("creation:"+pub_key.toString());
	    	//Built the JWT Token using RSA key pairs with uid as claims and username as subject and audience as clientid
	    	String token = Jwts.builder()
       		      //Using this endpoint the client can validate the public key by send the clientID along with request to this endpoint
       		     //returned public key should matched with issued public key in ID Token
       		     .setClaims(id_claims)
           		 .setIssuedAt(Date.from(Instant.now()))
           		 .setHeaderParam("alg",SignatureAlgorithm.RS512)
           		 .setHeaderParam("kid",pub_key)
           		 .signWith(SignatureAlgorithm.RS512, decodeBytesToKeys(private_key))
                   //Id token valid upto for 20 min
                  .setExpiration(Date.from(Instant.now().plus(20l, ChronoUnit.MINUTES)))
           		.compact();
            return token;
	    }
	    
	    public static PrivateKey decodeBytesToKeys(byte[] private_keys) throws NoSuchAlgorithmException, InvalidKeySpecException
	    {
	    	KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    	//Baeed on the keys format we need to get encoded
	    	//public key format : X509
	    	//private key format : PKCS#8
	        PKCS8EncodedKeySpec publicKeySpec = new PKCS8EncodedKeySpec(private_keys);
	        PrivateKey privatekeys = keyFactory.generatePrivate(publicKeySpec);
	        return privatekeys;
	    }
	    //Extract Time used for validate the Access token and Authorization code
	    public static String timeGenerator(int timeincrease) 
	    {
	 		      Calendar cal = Calendar.getInstance();
	 		      cal.add(Calendar.MINUTE, timeincrease);
	 		      return cal.getTime().toString();
	    }
	    
	  //Functions will gets invoked when you need to delete the session values by pass the session parameters
	    public static void deleteSessionValues(HttpServletRequest req,String delSessions)
	    {
	    	HttpSession session=req.getSession();
	    	session.removeAttribute(delSessions);
	    }
}
