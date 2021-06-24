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
<h1>Create An Account</h1>
<form action="msOIDC/msaccounts/createAcc">
<input type="text" placeholder="Enter your name" name="crename"><br><br><br>
<input type="email" placeholder="Enter your email" name="cremail"><br><br><br>
<input type="password" placeholder="Enter your password" name="crepass"><br><br><br>
<input type="number" placeholder="Enter your mobileno" name="cremobile"><br><br><br>
<input type="text" placeholder="Enter your location" name="creloc"><br><br><br>
<input type="submit" value="Create"><br><br><br>
</form>
</center>
</body>
</html>