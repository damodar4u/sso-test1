<html>
<body>
    <h1>Welcome to the SSO Application</h1>
    <p>User Info: ${sessionScope.user != null ? sessionScope.user.username() : "No user information available"}</p>
</body>
</html>
