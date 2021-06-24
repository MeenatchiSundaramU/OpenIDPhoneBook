<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1" import="java.util.*"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Developer Console</title>
</head>
<body>
<center>
<h1>WELCOME TO DEVELOPER CONSOLE</h1>
<form action="msOIDC/msdev/newClient">
<input type="text" placeholder="Enter your app name" name="appname"><br><br>
<input type="text" placeholder="Enter your redirected uri1" name="url1"><br><br>
<input type="text" placeholder="Enter your redirected uri2" name="url2"><br><br>
<input type="text" placeholder="Enter your redirected uri3" name="url3"><br><br>
<h3>Copy the ClientID and Client Secret</h3>
<% 
   int lLimit = 97; 
   int rLimit = 122; 
   int targetStringLength =10;
   Random random = new Random();
   String clientID= "mano."+random.ints(lLimit, rLimit + 1)
     .limit(targetStringLength)
     .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
     .toString();
   String clientSecret="mano."+random.ints(lLimit, rLimit + 1)
		     .limit(targetStringLength)
		     .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
		     .toString();
   session.setAttribute("clientID",clientID);
   session.setAttribute("clientSecret",clientSecret);
%>
<%="Client ID = "+clientID %><br><br>
<%="Client Secret = "+clientSecret %><br><br>
<input type="submit">
</form>
</center>
</body>
</html>