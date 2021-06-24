<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>MS PHONE BOOK HOME PAGE</title>
</head>
<body>
<center>
<h1>WELCOME TO MS PHONE BOOK</h1>
<h3>
<%
    String name=(String)session.getAttribute("enduser_name");
    out.println("Welcome "+name);
%>
</h3>
<a href="msPhoneBook/userinfo"><input type="submit" value="Access Profile From Mano"></a>
</center>
</body>
</html>