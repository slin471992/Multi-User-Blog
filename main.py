# Udacity Project 3: Multi User Blog
# Shumei Lin

import os
import re
import random
import hashlib
import hmac

import webapp2
import jinja2

from string import letters
from google.appengine.ext import db
from urlparse import urlparse

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class MainHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # get current post_id from url
    def url_post(self):
        # get current url
        current_url = str(self.request.url)
        # get current post id
        post_id = int(current_url.split("/")[4])
        return post_id

    # get current comment_id from url
    def url_comment(self):
        # get current url
        current_url = str(self.request.url)
        # get current post id
        comment_id = int(current_url.split("/")[6])
        return comment_id

    # get current user name from cookie "user_id"
    def current_username(self):
        cookie_val = self.request.cookies.get("user_id")
        user_id = check_secure_val(cookie_val)
        key = db.Key.from_path('User', int(user_id), parent=users_key())
        user = db.get(key)
        username = user.username
        return username

# comment stuff


def comment_key(name='default'):
    return db.Key.from_path('comments', name)

# the Comment database


class CommentDB(db.Model):
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    author = db.StringProperty(required=True)

    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# like stuff
def like_key(name='default'):
    return db.Key.from_path('likes', name)

# the Like database


class LikeDB(db.Model):
    post_id = db.IntegerProperty(required=True)
    like_by = db.StringProperty(required=True)
    like_value = db.IntegerProperty(required=True)

    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# the Post database


class Post(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)

    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

# user stuff


def users_key(group='default'):
    return db.Key.from_path('users', group)

# the User database


class User(db.Model):
    username = db.StringProperty(required=True)
    hash_password = db.StringProperty(required=True)
    email = db.StringProperty()

# cookies stuff
secret = "fart"


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# hash password stuff


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# render the home page, list the most recent 3 blog posts
class BlogPage(MainHandler):

    def render_blog(self):
        posts = db.GqlQuery(
            "SELECT * FROM Post ORDER BY last_modified DESC LIMIT 10")

        self.render("blog.html", posts=posts)

    def get(self):
        self.render_blog()

# render the /newpost page


class NewPost(MainHandler):

    def render_newpost(self, title="", content="", error=""):
        self.render("newpost.html", title=title, content=content, error=error)

    def get(self):
        # check if user is logged in / check if there is a user_id cookie
        if self.read_secure_cookie("user_id"):
            self.render_newpost()

        else:
            error = ("Error: You are not logged in")
            self.render("error-form.html", error=error)

    def post(self):
        # check if user is logged in / check if there is a user_id cookie
        if self.read_secure_cookie("user_id"):
            # get current username as author to store in new post database
            author = self.current_username()

            title = self.request.get("title")
            content = self.request.get("content")

            # add new post to database
            if title and content:
                p = Post(parent=blog_key(), title=title,
                         content=content, author=author, likes=0)
                p.put()
                self.redirect("/%s" % str(p.key().id()))

            else:
                error = "Error: We need both a title and some contents!"
                self.render_newpost(title, content, error)


# render the /post_id page
class PostPage(MainHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = CommentDB.all().filter(
                    "post_id = ", int(post_id)).order("-last_modified")
        likes = db.GqlQuery(
            "SELECT * from LikeDB WHERE post_id = :1", int(post_id))

        like_total = 0
        if likes:
            for like in likes:
                like_total += like.like_value

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post,
                    comments=comments, like_total=like_total)

# Comment on a single post


class Comment(MainHandler):

    def get(self):
        # make sure user is logged in in order to comment / check if there is
        # user_id cookie
        if self.read_secure_cookie("user_id"):
            self.render("comment-form.html")

        else:
            error = ("Error: You are not logged in")
            self.render("error-form.html", error=error)

    def post(self):
        comment = self.request.get("comment")
        # make sure user is logged in in order to comment / check if there is
        # user_id cookie
        if self.read_secure_cookie("user_id"):
            # get current post id
            post_id = self.url_post()
            # check if user enter any comments
            if comment:
                # get current username to store as author in the comment
                # database
                author = self.current_username()
                # put the comment into the comment database
                c = CommentDB(parent=comment_key(), post_id=post_id,
                              comment=comment, author=author)
                c.put()
                self.redirect("/%s" % str(post_id))
            else:
                error = "Error: You need to enter some comments"
                self.render("comment-form.html", error=error)

# Edit or Delete comments


class CommentEdit(MainHandler):

    def render_comment_edit(self, comment="", error=""):
        self.render("comment-edit-form.html", comment=comment, error=error)

    def get(self):
        # check if user is logged in
        if self.read_secure_cookie("user_id"):
            # get current username
            username = self.current_username()

            # get current comment id
            comment_id = self.url_comment()

            # get comment author name
            key = db.Key.from_path('CommentDB', int(
                comment_id), parent=comment_key())
            c = db.get(key)
            comment_author = c.author

            comment = c.comment
            if username == comment_author:
                self.render_comment_edit(comment)

            else:
                error = "Error: You don't have permission to edit/delete"
                post_id = self.url_post()
                self.render("blog-error-form.html",
                            error=error, post_id=str(post_id))

        else:
            error = "Error: You are not logged in"
            self.render("error-form.html", error=error)

    def post(self):
        action = self.request.get("action")
        comment = self.request.get("comment")

        # make sure user is logged in in order to comment / check if there is
        # user_id cookie
        if self.read_secure_cookie("user_id"):
            # get current username
            username = self.current_username()

            # get current comment id and post id
            comment_id = self.url_comment()
            post_id = self.url_post()

            # get comment author name
            key = db.Key.from_path('CommentDB', int(
                comment_id), parent=comment_key())
            c = db.get(key)
            comment_author = c.author

            if username == comment_author:
                # can edit/delete
                if action == "edit_save":
                    c.comment = comment
                    c.put()
                elif action == "delete":
                    c.delete()
                    self.response.out.write("deletion done")

                self.redirect("/%s" % str(post_id))


# Like a single post
class Like(MainHandler):

    def get(self):
        # check if user is logged in by checking the "user_id" cookies
        if self.request.cookies.get("user_id"):
            # get current username
            username = self.current_username()

            # get current post id
            post_id = self.url_post()
            # get post author name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = str(post.author)

            if username == post_author:
                error = "Error: You cannot like/unlike your own posts!"
                self.render("blog-error-form.html",
                            post_id=post_id, error=error)

            else:
                self.render("like-form.html")

        else:
            error = ("Error: You are not logged in")
            self.render("error-form.html", error=error)

    def post(self):
        action = self.request.get("action")

        if self.request.cookies.get("user_id"):
            # get current username
            username = self.current_username()

            # # get current post id
            post_id = self.url_post()
            # get post author name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = str(post.author)

            if username != post_author:
                like_already = LikeDB.all().filter(
                    "post_id = ", post_id).filter("like_by = ", username).get()
                if action == "like":
                    # check if user has already liked the post
                    if like_already is None:
                        l = LikeDB(parent=like_key(), post_id=post_id,
                                   like_value=1, like_by=username)
                        l.put()
                        self.redirect("/%s" % str(post_id))

                    else:
                        error = "Error: You can only like the post once"
                        self.render("blog-error-form.html",
                                    post_id=post_id, error=error)

                elif action == "unlike":
                    if like_already is None:
                        error = ("Error: you haven't like the post,"
                                 " so you cannot cancel your like")
                        self.render("blog-error-form.html",
                                    post_id=post_id, error=error)

                    else:
                        # delete current like from like database
                        like_already.delete()
                        self.redirect("/%s" % str(post_id))


# Delete a single post
class Delete(MainHandler):

    def get(self):
        # check if user is logged in by checking the "user_id" cookies
        if self.request.cookies.get("user_id"):
            # get current username
            username = self.current_username()

            post_id = self.url_post()
            # get post author name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = str(post.author)

            if username == post_author:
                self.render("delete-form.html")
            else:
                error = "Error: You don't have permission to delete the post"
                self.render("blog-error-form.html",
                            post_id=post_id, error=error)

        else:
            error = ("Error: You are not logged in")
            self.render("error-form.html", error=error)

    def post(self):
        action = self.request.get("action")
        # check if user is logged in
        if self.request.cookies.get("user_id"):
            # get current username
            username = self.current_username()

            post_id = self.url_post()
            # get post author name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = str(post.author)

            # can delete their own posts
            if username == post_author:
                if action == "delete":
                    # delete comments of the post
                    comments = db.GqlQuery(
                        "SELECT * from CommentDB WHERE post_id = :1",
                        int(post_id))
                    for c in comments:
                        c.delete()

                    # delete likes of the post
                    likes = db.GqlQuery(
                        "SELECT * from LikeDB WHERE post_id = :1",
                        int(post_id))
                    for l in likes:
                        l.delete()

                    # delete the post itself
                    post.delete()
                    self.response.out.write("deletion done")
                    self.redirect("/")
                else:
                    self.redirect("/%s" % str(post_id))


# Edit a single post
class Edit(MainHandler):

    def render_edit(self, title="", content="", error=""):
        self.render("edit-form.html", title=title,
                    content=content, error=error)

    def get(self):
        if self.request.cookies.get("user_id"):
            username = self.current_username()
            post_id = self.url_post()
            # get post author name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = str(post.author)

            if username == post_author:
                title = post.title
                content = post.content
                self.render_edit(title, content)

            else:
                error = "Error: You don't have permission to edit the post"
                self.render("blog-error-form.html",
                            post_id=post_id, error=error)

        else:
            error = "Error: You are not logged in"
            self.render("error-form.html", error=error)

    def post(self):
        action = self.request.get("action")
        content = self.request.get("content")

        if self.request.cookies.get("user_id"):
            username = self.current_username()
            post_id = self.url_post()
            # get post author name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post_author = str(post.author)

            # can edit
            if username == post_author:
                # save changes
                if action == "edit_save":
                    post.content = content
                    post.put()

                self.redirect("/%s" % str(post_id))


# validate username, password, email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def password_match(p1, p2):
    return p1 == p2

# user sign up/registration


class Signup(MainHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        user_username = self.request.get("username")
        user_password = self.request.get("password")
        user_verify = self.request.get("verify")
        user_email = self.request.get("email")

        params = dict(username=user_username,
                      email=user_email)

        have_error = False

        if not valid_username(user_username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(user_password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif (valid_password(user_password) and
              password_match(user_password, user_verify) is False):
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(user_email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)

        else:
            # check if the username already exists
            user_exist = User.all().filter("username = ", user_username).get()
            # username already exists
            if user_exist:
                error_username = "Username already exists."
                self.render("signup-form.html", error_username=error_username)

            else:
                # register the new user, put the new user into User database,
                # and set cookie
                if user_username and user_password:
                    hash_password = make_pw_hash(user_username, user_password)
                    u = User(parent=users_key(), username=user_username,
                             hash_password=hash_password, email=user_email)
                    u.put()

                    self.set_secure_cookie("user_id", str(u.key().id()))
                    self.redirect("/welcome?username=" + str(u.username))


class Welcome(MainHandler):

    def get(self):
        if self.request.cookies.get("user_id"):
            current_username = self.current_username()
            username = self.request.get("username")
            if username == current_username:
                self.render("welcome.html", username=username)

            else:
                self.redirect("/signup")

        else:
            self.redirect("/signup")


class Login(MainHandler):

    def get(self):
        self.render("login-form.html")

    def post(self):
        login_username = self.request.get("username")
        login_password = self.request.get("password")

        params = dict(username=login_username)

        have_error = False

        # verify if user name is registered (in the User database) and verify
        # password
        user_exist = User.all().filter("username = ", login_username).get()
        if user_exist:
            if valid_pw(login_username, login_password,
                        user_exist.hash_password):
                # login the user
                # set cookie
                self.set_secure_cookie("user_id", str(user_exist.key().id()))
                self.redirect("/welcome?username=" + str(login_username))
            else:
                params["error_password"] = "Password is not correct"
                self.render("login-form.html", **params)
        else:
            params["error_username"] = "Username does not exist"
            self.render("login-form.html", **params)


class Logout(MainHandler):

    def get(self):
        # clear cookies
        if self.read_secure_cookie("user_id"):
            self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
            msg = "You have been logged out"
            self.render("logout-form.html", msg=msg)

        else:
            error = "Error: You are not logged in"
            self.render("error-form.html", error=error)


app = webapp2.WSGIApplication([
    ('/', BlogPage),
    ('/newpost', NewPost),
    ('/([0-9]+)', PostPage),
    ('/signup', Signup),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ('/comment/[0-9]+', Comment),
    ('/like/[0-9]+', Like),
    ('/delete/[0-9]+', Delete),
    ("/edit/[0-9]+", Edit),
    ("/comment/[0-9]+/edit/[0-9]+", CommentEdit)
], debug=True)
