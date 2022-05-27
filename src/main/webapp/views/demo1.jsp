<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
	<c:out value="${name}">
		<h1>Welcome</h1>
	</c:out>
	<hr>
	<hr>
	<a href="demo2">Call demo 2</a>
	<hr>
	<hr>
	<form action="logout" method="post">
		<input type="hidden" name="${_csrf.parameterName}"
			value="${_csrf.token}" />
		<button>Logout</button>
	</form>
	<hr>
	<hr>
</body>
</html>