<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ taglib uri="http://java.sun.com/jstl/core_rt" prefix="c" %>

<%--
  Copyright 2012 SURFnet bv, The Netherlands

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  --%>

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
  <title>Mujina Login Page</title>
  <link href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/css/bootstrap-combined.min.css" rel="stylesheet">
</head>
<body onload='document.login.j_username.focus();'>

<pre style="front-weight: bold;">
___  ___        _  _
|  \/  |       (_)(_)
| .  . | _   _  _  _  _ __    __ _
| |\/| || | | || || || '_ \  / _` |
| |  | || |_| || || || | | || (_| |
\_|  |_/ \__,_|| ||_||_| |_| \__,_|
              _/ |
             |__/

          Identity Provider
</pre>

<div class="container">

  <c:if test="${not empty SPRING_SECURITY_LAST_EXCEPTION }">
    <p><font color='red'>Your login attempt was not successful, try again.<br/><br/>Reason: <c:out
        value="${SPRING_SECURITY_LAST_EXCEPTION.message}"/></font></p>
  </c:if>

  <h3>Login with Username and Password</h3>

  <form name='login' action='j_spring_security_check' method='POST' class='form-horizontal'>

        <label for='j_username'>User:</label>
        <input type='text' name='j_username' id='j_username' value=''>

        <label for='j_password'>Password:</label>
        <input type='password' name='j_password' id='j_password'/>

        <input name="submit" type="submit" value="Login" class="btn btn-success"/>

  </form>

</div>
</body>
</html>