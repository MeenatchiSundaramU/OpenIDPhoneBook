<%@page import="java.util.ArrayList"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<center>
<h1>WELCOME TO DEVELOPER HOME PAGE</h1>
<% 
     ArrayList<Object> dev_name=(ArrayList)session.getAttribute("log_user_details");
      out.println("WELCOME "+(String)dev_name.get(1));
%>
<br><br>
<a href="developerConsole.jsp"><input type="submit" value="Create New Client"></a><br><br>
<a href="RetrieveClientCred.jsp"><input type="submit" value="Exist Client Info"></a><br><br>
<a href="msOIDC/developer/logout"><input type="submit" value="LOG OUT"></a><br><br><br><br><br><br>
</center>
</body>
</html>