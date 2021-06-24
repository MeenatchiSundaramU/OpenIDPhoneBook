<%@page import="OpenIDModel.SaveAuthParamModel"%>
<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
    <%@page import="java.util.Map"%>
    <%@page import="java.util.ArrayList"%>
<%@page import="java.util.HashMap"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<center>
<h1>Confirmation required from the Resource Owner</h1>
<%
  String appname=(String)((Map<String,Object>)session.getAttribute("client_credentials")).get("appname");
  String res_own_name=(String)((ArrayList)session.getAttribute("log_user_details")).get(1);
  String scope=(String)((SaveAuthParamModel)session.getAttribute("saveAuthParam")).getScope();
%>
<h3>Hey,<%=res_own_name %></h3>
<h3><%=appname %>App want to allow to access the following resources</h3>
<% 
      out.print("Client going to access the ");
      out.print(scope+"\n");
%>
<br><br><br>
<a href="msOIDC/codeortoksent"><input type="submit" value="Allow"></a><br><br>
<a href="msOIDC/grantdenied"><input type="submit" value="Deny"></a>
</center>
</body>
</html>