<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/sql" prefix="sql" %>   
<%@page import="java.util.ArrayList"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Developers Existing Clients</title>
</head>
<body>
    <sql:setDataSource
        var="lsOfClients"
        driver="org.sqlite.JDBC"
        url="jdbc:sqlite:C://sqlite-tools-win32-x86-3350500//msOIDC.db"
    />
     <% 
     ArrayList<Object> dev_name=(ArrayList)session.getAttribute("log_user_details");
     %>
    <sql:query var="listClients"   dataSource="${lsOfClients}">
        SELECT * FROM developerdb WHERE uid=<%=dev_name.get(0)%>
    </sql:query>
     
    <div align="center">
        <table border="1" cellpadding="5">
            <caption><h2>List of Clients</h2></caption>
            <tr>
                <th>ClientID</th>
                <th>ClientSecret</th>
                <th>AppName</th>
                <th>RedirectedURI</th>
            </tr>
            <c:forEach var="dev" items="${listClients.rows}">
                <tr>
                    <td><c:out value="${dev.clientid}" /></td>
                    <td><c:out value="${dev.clientsecret}" /></td>
                    <td><c:out value="${dev.appname}" /></td>
                    <td><c:out value="${dev.redirecturis}" /></td>
                </tr>
            </c:forEach>
        </table>
    </div>
</body>
</html>