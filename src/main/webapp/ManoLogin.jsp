<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Log In</title>
</head>
<body>
<center>
<h1>Welcome to Login Page</h1>
<form action="msOIDC/msaccounts/login">
<input type="email" placeholder="Enter your email" name="logmail"><br><br><br>
<input type="password" placeholder="Enter your password" name="logpass"><br><br><br>
<input type="submit" value="Log In"><br><br><br>
</form>
<a href="CreateAccount.jsp"><button>Create an Account</button></a><br><br><br>
<%
String invalid_login=(String)session.getAttribute("invalid_login");
if(invalid_login!=null)
	out.print("Invalid Login");
%>
</center>
</body>
</html>