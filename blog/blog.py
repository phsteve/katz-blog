#Author: Stephen Katz

import os
import webapp2
import jinja2
import re
import hashlib
import json
import logging
import time

from google.appengine.ext import db
from google.appengine.api import memcache
from google.appengine.ext.webapp.util import run_wsgi_app

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    #convenience functions in a basic Handler class
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    posted = db.DateTimeProperty(auto_now_add = True, )
    author = db.StringProperty(required = False)

class UserAccount(db.Model):
    username = db.StringProperty(required = True)
    salted_hashed_pw = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

def top_posts(update=False):
    #caches the top ten posts or creates a cache if none exists
    key = 'top'
    blog_posts = memcache.get(key)
    if blog_posts is None or update:
        logging.error("DB QUERY")
        blog_posts = db.GqlQuery("select * from BlogPost order by posted desc limit 10")
        blog_posts = list(blog_posts)
        memcache.set(key, blog_posts)
        memcache.set('time_set', int(time.time()))
    return blog_posts, memcache.get('time_set')

def permalink_cache(post_id, update=False):
    #caches the single post on permalink page or creates a cache
    key = 'post'
    blog_post = memcache.get(key)
    if blog_post is None or update:
        logging.error("DB QUERY")
        blog_post = BlogPost.get_by_id(int(post_id))
        memcache.set(key, blog_post)
        memcache.set('time_set', int(time.time()))
    return blog_post, memcache.get('time_set')

class MainPage(Handler):
    def render_front(self, error=""):
        blog_posts, time_set = top_posts()
        if time_set:
            seconds_since_query = int(time.time()) - time_set
        else:
            seconds_since_query = 0
        user_id = self.request.cookies.get('user_id')
        if user_id:
            user_id = self.request.cookies.get('user_id').split('|')[0]
        self.render("blogfront.html", blog_posts=blog_posts, seconds_since_query=seconds_since_query, user_id=user_id)

    def get(self):
        self.render_front()

class NewPost(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        author = self.request.cookies.get('user_id').split('|')[0]

        if subject and content:
            p = BlogPost(subject=subject, content=content, author=author)
            p.put()
            #redirect to permalink page
            self.redirect('/blog/%d' %(p.key().id()))
        else:
            error = "we need both a subject and content!"
            self.render_newpost(subject, content, error)

class PermalinkPage(Handler):
    def get(self, post_id):
        blog_post, time_set = permalink_cache(post_id, update=True)
        if time_set:
            seconds_since_query = int(time.time()) - time_set
        else:
            seconds_since_query = 0
        self.render("permalink.html", blog_post=blog_post, seconds_since_query = seconds_since_query)

##Signup handling

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_username(s):
    return USER_RE.match(s)
def valid_pw(s):
    return PW_RE.match(s)
def valid_email(s):
    return EMAIL_RE.match(s)

#cookie/username/password hashing functions
USERNAME_SALT = "BDRUBILNUVENISLVNILSIJOSVPQOIJXNKLBNJBDXIJDDBFKEBYJRGCFDSOWP"
PASSWORD_SALT = "ENBOIOQQENEFNOBFJKPOBGJVNDVIUEGWIOURHERGHFGTFTFGHHMNMVJNBHKC"

def hash_pw(pw):
    return hashlib.sha256(pw + PASSWORD_SALT).hexdigest()

def hash_cookie(user_id):
    return "%s|%s" % (user_id, hashlib.sha256(user_id + USERNAME_SALT).hexdigest())

def check_hash(h):
    val = h.split('|')[0]
    if hash_cookie(val) == h:
        return val

class SignupHandler(Handler):
    #handles signing up for new user accounts
    def render_signup(self, username="", username_error="", email="", email_error="", pw_error="", verify_error=""):
        self.render("signup.html", username=username, username_error=username_error, email=email,
                    email_error=email_error, pw_error=pw_error, verify_error=verify_error)

    def get(self):
        self.render_signup()

    def post(self, username="", email=""):
        #username and email validation
        username = str(self.request.get("username"))
        v_username = valid_username(username)
        email = self.request.get("email")
        v_email = valid_email(email)
        pw = self.request.get("password")
        v_pw = valid_pw(pw)
        verifypw = self.request.get("verify")

        if (pw == verifypw) and v_username and (not email or v_email) and v_pw:
            same_username = UserAccount.gql("WHERE username = '%s'" % username)
            if same_username.count(limit=1):
                username_error = "Theres someone with that name already!"
                self.render_signup(username_error=username_error)
            else:
                salted_hashed_pw = hash_pw(pw)
                if v_email:
                    u = UserAccount(username = username, salted_hashed_pw = salted_hashed_pw, email = email)
                if not email:
                    u = UserAccount(username = username, salted_hashed_pw = salted_hashed_pw)
                u.put()
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie', 'user_id=' + hash_cookie(username), Path='/')
                self.redirect('/blog/success')

        else:
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
            if (not v_email) and email:
                email_error = "Please enter a valid email."
            self.render_signup(username, username_error, email, email_error, pw_error, verify_error)

class SuccessHandler(Handler):
    #on successful login
    def get(self):
        h = self.request.cookies.get('user_id')
        if check_hash(h):
            self.response.out.write("Welcome, %(username)s!" %{"username": h.split('|')[0]})
            self.response.out.write("<br><a href='/blog'>Main blog page</a>")
        else:
            self.redirect('/blog/signup')

class LoginHandler(Handler):
    #check username and password, redirect to welcome page with correct cookie
    #if invalid, show invalid password error message

    def render_login(self, username="", username_error="", pw_error=""):
        self.render("login.html", username=username, username_error=username_error, pw_error=pw_error)

    def get(self):
        self.render_login()

    def post(self):
        #check if username is in db
        username = str(self.request.get("username"))
        pw = self.request.get("password")
        user_data = UserAccount.gql("WHERE username = '%s'" % username)
        if user_data.count(limit=1):
            if hash_pw(pw) == user_data.get().salted_hashed_pw:
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie', 'user_id=' + hash_cookie(username), Path='/')
                self.redirect('/blog/success')
            else:
                self.render_login(username=username, pw_error = "Incorrect password.")
        else:
            self.render_login(username_error = "That user doesn't exist.")

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=', Path='/')
        self.redirect('/blog')

class CookieTestHandler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = self.request.cookies.get('visits', '0')
        #make sure visits is an int
        if visits.isdigit():
            visits = int(visits) + 1
        else:
            visits = 0
        self.response.headers.add_header('Set-Cookie', 'visits = %s' % visits)
        self.write("You've been here %s times!\n" % visits)
        if visits > 100:
            self.write("Holy cow you're awesome!")

class JSONMainPage(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'application/json'
        j = []
        blog_posts = db.GqlQuery("select * from BlogPost order by posted desc")
        for blog_post in blog_posts:
            j.append({"subject": blog_post.subject,
                      #"posted": blog_post.posted,
                      "content": blog_post.content})
        jdumped = json.dumps(j)
        self.write(jdumped)

class JSONPermalinkPage(Handler):
    def get(self, post_id):
        self.response.headers['Content-Type'] = 'application/json'
        blog_post = BlogPost.get_by_id(int(post_id))
        j = {"subject": blog_post.subject, "content": blog_post.content}
        self.write(json.dumps(j))

class FlushHandler(Handler):
    #Flushes the cache, fixes prior problem of front page missing the most recent post
    def get(self):
        top_posts(update=True)
        self.redirect('/blog')

app = webapp2.WSGIApplication([(r'/blog/?', MainPage),
                               ('/blog/newpost', NewPost),
                               (r'/blog/(\d+)', PermalinkPage),
                               ('/blog/signup', SignupHandler),
                               ('/blog/success', SuccessHandler),
                               ('/blog/login', LoginHandler),
                               ('/blog/logout', LogoutHandler),
                               ('/blog/.json', JSONMainPage),
                               (r'/blog/(\d+).json', JSONPermalinkPage),
                               ('/blog/flush', FlushHandler),
                               ('/cookietest', CookieTestHandler)],
                              debug = True)

def blog():
    util.run_wsgi_app(app)
if __name__ == '__main__':
    blog()