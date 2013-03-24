<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

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
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <title>Mujina</title>
    <script src="//ajax.googleapis.com/ajax/libs/jquery/1.8.2/jquery.min.js"></script>
    <script type="text/javascript">
        $(document).ready(function(){
            var request;
            $("#adduser").submit(function(event){
                var $form = $(this);
                var $inputs = $form.find("input");
                var serializedData = $form.serialize();
                $inputs.prop("disabled", true);
                var request = $.ajax({
                    url: "/api/users",
                    type: "post",
                    data: serializedData
                });

                request.done(function (response, textStatus, jqXHR){
                    console.log("User added!");
                    $("#form_result").text("User added!")
                });

                request.fail(function (jqXHR, textStatus, errorThrown){
                    console.error("Error occured: " + textStatus, errorThrown);
                    $("#form_result").text("User could not be added!")
                });

                request.always(function () {
                    $inputs.prop("disabled", false);
                });
                event.preventDefault();
            });
        });
    </script>
</head>

<body>

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

<h1>Identity Provider Admin Page</h1>

<h3>This page is secured. You must have the ROLE_ADMIN authority to be here.</h3>

<a href="index.jsp">unprotected home page</a> <br/>
<a href="user.jsp">protected user page</a> <br/>
<a href="j_spring_security_logout">End your session with the Identity Provider</a>
<i>Does not end your session with theSP</i> <br/>

<h3>Your current Spring Security Credentials are:</h3>

<H4>Authentication Principal is: </H4>

<p><sec:authentication property="principal"></sec:authentication></p>
<H4>Authentication Credentials are: </H4>

<p><sec:authentication property="credentials"></sec:authentication></p>
<H4>Authentication Details are: </H4>

<p><sec:authentication property="details"></sec:authentication></p>

<h4>Add user</h4>
<form action="#" method="POST" id="adduser">
    Username: <input name="username" type="text" size="50"><br />
    Password: <input name="password" type="text" size="50"><br />
    Roles: <input name="roles" type="text" value="ROLE_USER,ROLE_ADMIN" size="50"> <br />
    <input type="submit" value="Add user">
</form>
<div id="form_result"></div>

</body>

</html>
