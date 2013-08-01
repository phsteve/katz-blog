#!/usr/bin/env python

import webapp2
import cgi
import string
import re

signup_html = """
<form method="post">
    <h1>Signup</h1>
    <label>
        Username
        <input type="text" name="username" value="%(username)s">
    </label>
    %(username_error)s
    <br>
    <label>
        Password
        <input type="password" name="password" value="">
    </label>
    %(pw_error)s
    <br>
    <label>
        Verify Password
        <input type="password" name="verify" value="">
    </label>
    %(verify_error)s
    <br>
    <label>
        Email (optional)
        <input type="text" name="email" value="%(email)s">
    </label>
    %(email_error)s
    <br>
    <input type="submit">
</form>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(s):
    return USER_RE.match(s)
def valid_pw(s):
    return PW_RE.match(s)
def valid_email(s):
    return EMAIL_RE.match(s)

class SignupHandler(webapp2.RequestHandler):
    def write_page(self, username="", username_error="", email="", email_error="", pw_error="", verify_error=""):
        self.response.out.write(signup_html%{"username": username,
                                             "username_error": username_error,
                                             "email": email,
                                             "email_error": email_error,
                                             "pw_error": pw_error,
                                             "verify_error": verify_error
                                             })

    def get(self):
        self.write_page()

    def post(self, username="", email=""):
        username = self.request.get("username")
        v_username = valid_username(username)
        email = self.request.get("email")
        v_email = valid_email(email)
        pw = self.request.get("password")
        v_pw = valid_pw(pw)
        verifypw = self.request.get("verify")

        if (pw == verifypw) and v_username and (not email or v_email) and v_pw:
            self.redirect('/success?username=%(username)s'%{"username": username})

        else:
            #Something about default values in write_page isn't right
            pw_error = ""
            username_error = ""
            email_error = ""
            verify_error = ""

            if (pw != verifypw):
                verify_error = "Please enter a matching password."
            if not v_pw:
                pw_error = "Please enter a valid, matching password."
            if not v_username:
                username_error = "Please enter a valid username."
            if not v_email:
                email_error = "Please enter a valid email."
            self.write_page(username, username_error, email, email_error, pw_error, verify_error)




class SuccessHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        self.response.out.write("Your account has successfully been created, %(username)s!" %{"username": username})

app = webapp2.WSGIApplication([('/blog/signup', SignupHandler),
                               ('/blog/success', SuccessHandler)],
                              debug=True)


