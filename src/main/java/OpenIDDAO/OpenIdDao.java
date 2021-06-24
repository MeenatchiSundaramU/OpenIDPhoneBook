package OpenIDDAO;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import OpenIDModel.AccessTokenModel;
import OpenIDModel.CreateAccModel;
import OpenIDModel.DeveloperModel;
import OpenIDModel.RefreshTokenModel;
import OpenIDModel.grantCodeModel;

public class OpenIdDao 
{
	     //Connect to openID Server Database 	
		public static Connection connect() throws ClassNotFoundException, SQLException
	    {
	   	 Class.forName("org.sqlite.JDBC");
	   	 Connection con=DriverManager.getConnection("jdbc:sqlite:C://sqlite-tools-win32-x86-3350500//msOIDC.db");
	   	 return con;
	    }
		//New Developer clients are inserted here
	    public static void InsertDeveloper(DeveloperModel newdev) throws ClassNotFoundException, SQLException
	    {
			 Connection conn=connect();
			 PreparedStatement st=conn.prepareStatement("insert into developerdb(uid,clientid,clientsecret,appname,redirecturis,rsapubkey,rsaprivatekey) values(?,?,?,?,?,?,?)");
			 st.setInt(1, newdev.getUid());
			 st.setString(2,newdev.getClientId());
			 st.setString(3,newdev.getClientSecret());
			 st.setString(4,newdev.getAppName());
			 st.setString(5, newdev.getRedirectUri());
			 st.setBytes(6, newdev.getRsaPubKey());
			 st.setBytes(7, newdev.getRsaPrivateKey());
			 st.executeUpdate();
			 st.close();
			 conn.close();
	    }
	    
	    //Insert new user when creating an new accounts
	    public static void InsertUser(CreateAccModel creuser,String refreshTokens) throws ClassNotFoundException, SQLException, NoSuchAlgorithmException
	    {
		 //Database connect
	   	 Connection conn=connect();
	   	 PreparedStatement st=conn.prepareStatement("insert into users(name,email,mobile,password,location) values(?,?,?,?,?)");
	   	 st.setString(1,creuser.getName());
	   	 st.setString(2,creuser.getEmail());
	   	 st.setString(3,creuser.getPhone());
	   	 st.setString(4,hashPass(creuser.getPassword()));
	   	 st.setString(5, creuser.getLocation());
	   	 
	   	 //Insertion made into database
	   	 st.executeUpdate();
	   	 
	   	 //Find the UID of the user to save the refresh token to that uid in refToken Holder
	     java.sql.Statement stm=(java.sql.Statement)conn.createStatement();
	     ResultSet rst=stm.executeQuery("select max(uid) as UID from users");
	     int uids=rst.getInt("UID");
	     stm.close();
	     rst.close();
	    
	     //Insert uids into UsersAPIindex table to acknowledge,which of the user's resources will hold by the server
	     st=conn.prepareStatement("insert into usersAPIindex(uid,profile,contacts) values(?,?,0)");
	     st.setInt(1, uids);
		 st.setInt(2,1);
		 st.executeUpdate();
		 
		 //Insert the 20 refresh Tokens for that Users Accounts which helpful for refreshing the access tokens during API calls
		 st=conn.prepareStatement("insert into refTokenHolder(uid,refreshTokens) values(?,?)");
		 st.setInt(1, uids);
		 st.setString(2,refreshTokens);
		 st.executeUpdate();
		 st.close();
		 conn.close();
	    }
	    
	  //Check the users credentials when logging the accounts
	  public static ArrayList<Object> checkUser(String email,String pass) throws ClassNotFoundException, SQLException, NoSuchAlgorithmException
	  {
		    ArrayList<Object> uid_uname=new ArrayList();
	  		Connection conn=connect();
	  		PreparedStatement st=conn.prepareStatement("select * from users where email=? and password=?");
	  		st.setString(1, email);
	  		st.setString(2, hashPass(pass));
	  		ResultSet rs=st.executeQuery();
	  		if(rs.next()==false)
	  	     {
	  			return uid_uname;
	  		 }
	  		else
	  		{
	  			uid_uname.add(rs.getInt("uid"));
	  			uid_uname.add(rs.getString("name"));
	  		}
	  		rs.close();
			st.close();
		    conn.close();
		    return uid_uname;
	  }
	    
	   //This function intention for Client Authentication
	   //Verify the client id as well as verified the client secret based on mode
	   //Mode-->0 Verified only clientID (arguments in client_credentials contains only clientID)
	  //Mode--->1 Verified ClientID and Client Secret(arguments client_credentials contains both clientID and clientsecret seperated by ,)
	  public static Map<String,Object> verifyDeveloper(String client_credentials,int mode) throws ClassNotFoundException, SQLException
	    {
	    	
	     //Initialsed the map which is going to holde the client credentials for future use like for issued ID token we need public and private key
	     //Then for verified redirected URI'S
	     Map<String,Object> dev_credentials = new HashMap<String,Object>();
	     String[] client_verify_querys= {"select * from developerdb where clientid=?","select * from developerdb where clientid=? and clientsecret=?"};
	     String[] clientCredentials=client_credentials.split(",");
	   	 Connection conn=connect();
	   	 PreparedStatement st=null;
	   	 
	   	//Verified only clientID
	   	 if(mode==0)
	   	 {
	   	 st=conn.prepareStatement(client_verify_querys[0]);
	   	 st.setString(1,clientCredentials[0]);
	   	 }
	   	 //Verified ClientID and Client Secret
	   	 else
	   	 {
	   		st=conn.prepareStatement(client_verify_querys[1]);
	   		st.setString(1,clientCredentials[0]);
		   	st.setString(2,clientCredentials[1]);
	   	 }
	   	 ResultSet rs=st.executeQuery();
	   	 if(rs.next()==true)
	   	 {
	   		dev_credentials.put("clientid",rs.getString("clientid"));
	   		dev_credentials.put("clientsecret",rs.getString("clientsecret"));
	   		dev_credentials.put("appname",rs.getString("appname"));
	   		dev_credentials.put("redirecturis",rs.getString("redirecturis"));
	   		dev_credentials.put("rsapubkey",rs.getBytes("rsapubkey"));
	   		dev_credentials.put("rsaprivatekey",rs.getBytes("rsaprivatekey"));
	   	 }
	   	 rs.close();
		 st.close();
		 conn.close();
	   	return dev_credentials;
	    }
	    
	  //Check the whether the resource owner have resources(which mentioned in the url) on mano's server
	  public static boolean checkScope(int uids,String scopename) throws SQLException, ClassNotFoundException
	  {
	  	 Connection conn=connect();
	  	 PreparedStatement st;
	  	 st=conn.prepareStatement("select * from usersAPIindex where uid=?");
	  	 st.setInt(1, uids);
	  	 ResultSet rs=st.executeQuery();
	  	 return checkResultSet(rs, conn, st, scopename);
	  }
	  		
	  //Resuablitity function for checking the resources on the resource server
	  	public static boolean checkResultSet(ResultSet rs,Connection conn,Statement st,String scopename) throws SQLException
	  		{
	  		  boolean scope_found=true;
	  		  String[] scopeSegregates=scopename.split(",");
	  		  if(rs.next()==false)
	  			{
	  				scope_found=false;
	  			}
	  		  else
	  		  {
	  			for(int i=0;i<scopeSegregates.length;i++)
	  		     {
	  			    if(rs.getInt(scopeSegregates[i])==0)
	  			     {
	  					scope_found=false;
	  					break;
	  				 }	
	  			 }
	  		   }
	  		   rs.close();
  			   st.close();
  			   conn.close();
	  		   return scope_found;
	  		}
	  	
	  	//Stored the Authorization grant code 
		public static void saveGrantCode(grantCodeModel newCode) throws SQLException, ClassNotFoundException
		{
			Connection conn=connect();
			PreparedStatement st=conn.prepareStatement("insert into grantcodelog(clientid,uid,grantcode,timestamp,scope,refreshissued) values(?,?,?,?,?,?)");
			st.setString(1,newCode.getClientId());
			st.setInt(2,newCode.getUid());
			st.setString(3,newCode.getGrantCode());
			st.setString(4,newCode.getTimeStamp());
		    st.setString(5,newCode.getScope());
			st.setInt(6,newCode.getRefresh_issued());
			st.executeUpdate();
		    st.close();
			conn.close();
		}
		//Save access token
		public static void saveAccessTokens(AccessTokenModel newAccessToken) throws SQLException, ClassNotFoundException
		{
			  Connection conn=connect();
			  PreparedStatement savetok=conn.prepareStatement("insert into issuedAccessToken(clientid,uid,accesstoken,scope,timestamp)values(?,?,?,?,?)");
			  savetok.setString(1, newAccessToken.getClientId());
			  savetok.setInt(2, newAccessToken.getUid());
			  savetok.setString(3, newAccessToken.getAccessToken());
			  savetok.setString(4,newAccessToken.getScope());
			  savetok.setString(5,newAccessToken.getTimeStamp());
			  savetok.executeUpdate();
			  savetok.close();
			  conn.close();
		}
			
		//save state parameters along with clientID
		public static void saveStateParam(String clientid,String state) throws SQLException, ClassNotFoundException
		{
			Connection conn=connect();
			PreparedStatement saveState=conn.prepareStatement("insert into checkCSRFtab(clientid,state)values(?,?)");
			saveState.setString(1,clientid);
			saveState.setString(2,state);
			saveState.executeUpdate();
			saveState.close();
			conn.close();
		}
		//Validation the grant code for generation of access token
		 public static ArrayList<Object> validateGrandCode(String grantcode) throws SQLException, ClassNotFoundException, ParseException
		  {
			 ArrayList<Object> uidrefstatus=new ArrayList();
			 Connection conn=connect();
			 PreparedStatement st=conn.prepareStatement("select * from grantcodelog where grantcode=?");
			 st.setString(1,grantcode);
			 ResultSet rs=st.executeQuery();
			 //Check if the code is avail or not
			 if(rs.next()==true)
			  {
				String grandtoktime=rs.getString("timestamp");
				//Indicates 0--->not issued refresh token , 1--> issued refresh token
				int refresh_issued=rs.getInt("refreshissued");
				int uid=rs.getInt("uid");
				String scope=rs.getString("scope");
			    Calendar tokcal = Calendar.getInstance();
			    SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
				tokcal.setTime((sdf.parse(grandtoktime)));
				Calendar currtime= Calendar.getInstance();
				st=conn.prepareStatement("delete from grantcodelog where uid=? and grantcode=?");
				st.setInt(1, rs.getInt("uid"));
				st.setString(2, grantcode);
				st.executeUpdate();
						   	 
				//Check for expiration of grantcode
				if((tokcal.compareTo(currtime)>0))
				{
				     uidrefstatus.add(uid);
					 uidrefstatus.add(refresh_issued);
					 uidrefstatus.add(scope);
				}
			    }
			    st.close();
				conn.close();
		   	    return uidrefstatus;
		    }
		//Get the username for that uids which is the subject identifier claim values for the ID tokens
		public static String getUserName(int uid) throws SQLException, ClassNotFoundException
		{
			Connection conn=connect();
			PreparedStatement st;
			st=conn.prepareStatement("select * from users where uid=?");
			st.setInt(1, uid);
			ResultSet rs=st.executeQuery();
			rs.next();
			String username=rs.getString("name");
			rs.close();
			return username;
		}
		//Save Refresh Token
		public static RefreshTokenModel saveRefreshToken(RefreshTokenModel refresh_token) throws ClassNotFoundException, SQLException
		{
			int tok_ind=1;
			String refreshTokens;
			Connection conn=connect();
			//Get max index of refresh token issued.
			PreparedStatement checkRefAvail=conn.prepareStatement("select max(tokenindex) as REMAIN from issuedRefreshToken where clientid=? and uid=?");
			checkRefAvail.setString(1, refresh_token.getClientId());
			checkRefAvail.setInt(2, refresh_token.getUid());
			ResultSet tokconsumes=checkRefAvail.executeQuery();
			if(tokconsumes.next()==false)
			{
				//If this is a first refresh token.
				refreshTokens=generateRefreshToken(refresh_token.getUid(),tok_ind, conn);
				refresh_token.setTokenindex(tok_ind);
				refresh_token.setRefreshToken(refreshTokens);
			}
			else
			{
				//It is used for providing the exact 20 refresh token,if 20 crossed,it will again issued the first refresh token which issued earlier.
				tok_ind=(((tokconsumes.getInt("REMAIN"))%20)+1);
				refresh_token.setTokenindex(tok_ind);
				refreshTokens=generateRefreshToken(refresh_token.getUid(),tok_ind,conn);
				refresh_token.setRefreshToken(refreshTokens);
			}
			tokconsumes.close();
			checkRefAvail.close();
			conn.close();
			return refresh_token;
		  }

		 //Validate the access tokens for API call
		public static int ValidateAccessToken(String accesstoken,String clientid,String scope) throws ClassNotFoundException, SQLException, ParseException
		{
			Connection conn=connect();
			int uid=0;
					
		   // To check whether this accesstoken is valid and scope mentioned in the URL should gets matched
		   PreparedStatement checktok=conn.prepareStatement("select * from issuedAccessToken where accesstoken=? and clientid=?");
		   checktok.setString(1, accesstoken);
		   checktok.setString(2, clientid);
		   ResultSet rscheck=checktok.executeQuery();
		   if(rscheck.next()==true)
		   {
				String actime=rscheck.getString("timestamp");
				Calendar cal = Calendar.getInstance();
			    SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
			    cal.setTime((sdf.parse(actime)));
			    Calendar cal2= Calendar.getInstance();
			    //if the access token is valid
				if(cal.compareTo(cal2)>0)
			     {
					 //Check the scope of issued accesstoken and scope mentioned in URL
					  if(rscheck.getString("scope").contains(scope)==true)
					   	{
						    uid=rscheck.getInt("uid");
					    }
			     }
			 }
		   rscheck.close();
		   checktok.close();
		   conn.close();
		   return uid;
		}
						
	   //Pick up and returned the Refresh Tokens which issued for respective accounts when the accounts was first created
		public static String generateRefreshToken(int uid,int tokind,Connection conn) throws SQLException
		{
			PreparedStatement getRefreshTok=conn.prepareStatement("select * from refTokenHolder where uid=?");
			getRefreshTok.setInt(1, uid);
			ResultSet refTok=getRefreshTok.executeQuery();
			refTok.next();
			String refTokens=refTok.getString("refreshTokens");
			String[] tokSegregate=refTokens.split(",");
			refTok.close();
			getRefreshTok.close();
			conn.close();
			return tokSegregate[tokind-1];
		}
						
		//Save Refresh Tokens after pickup from the refTokenHolder
		public static void saveRefreshTokens(RefreshTokenModel refToken) throws SQLException, ClassNotFoundException
		{
			Connection conn=connect();
			PreparedStatement saveReftok=conn.prepareStatement("insert into issuedRefreshToken(clientid,uid,refreshtoken,scope,tokenindex)values(?,?,?,?,?)");
			saveReftok.setString(1, refToken.getClientId());
			saveReftok.setInt(2, refToken.getUid());
			saveReftok.setString(3, refToken.getRefreshToken());
			saveReftok.setString(4,refToken.getScope());
			saveReftok.setInt(5, refToken.getTokenindex());
		    saveReftok.executeUpdate();
			conn.close();
		}
	    //It is used the hash the password using MD5 Hashing algo
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
