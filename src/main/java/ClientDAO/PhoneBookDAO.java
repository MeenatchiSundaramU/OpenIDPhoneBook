package ClientDAO;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class PhoneBookDAO 
{
	       //Connect to PhoneBook Server Database 	
		public static Connection connect() throws ClassNotFoundException, SQLException
		{
		   	 Class.forName("org.sqlite.JDBC");
		   	 Connection con=DriverManager.getConnection("jdbc:sqlite:C://sqlite-tools-win32-x86-3350500//phonebook.db;");
		   	 return con;
		}
		
	    //save accesstoken along with refresh token when accesstoken gets expired using refresh token we can get new accesstoken for that refresh token
		public static void saveTokens(String access_token,String refresh_token) throws SQLException, ClassNotFoundException
		{
			  Connection conn=connect();
			  PreparedStatement st=conn.prepareStatement("insert into refreshTokens(accesstoken,refreshtoken) values(?,?)");
			  st.setString(1,access_token);
			  st.setString(2,refresh_token);
			  st.executeUpdate();
			  st.close();
			  conn.close();
		}
}
