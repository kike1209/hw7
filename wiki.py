import webapp2
import cgi
import urlparse
import re
import os
import jinja2
from google.appengine.ext import ndb
import hmac
import logging
import time

"""
Udacity CS-253
Problem 7 - final - build a wiki
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PSW_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
COOKIE_RE = re.compile(r'.+=;\s*Path=/')
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
SECRET = 'mysaltedsecret'
DEBUG = True

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENVIRONMENT = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                       line_statement_prefix = '#',
                                       extensions=['jinja2.ext.autoescape'],
                                       autoescape = True)

# data kinds ---------------------------------------------------------

class Account(ndb.Model):
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty(indexed=False)

class WikiPage(ndb.Model):
    username = ndb.StringProperty(required=True)
    page_url =  ndb.StringProperty(required=True)
    content = ndb.StringProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now = True)
    
    @classmethod
    def query_wiki(cls, username, page_url, datetime=None):
        q = cls.query()
        q = q.filter(cls.username == username)
        q = q.filter(cls.page_url == page_url)
        if datetime is not None:
            q = q.filter(cls.last_modified == datetime)
        return q.order(-cls.last_modified)

      
# user management ----------------------------------------------------

def valid_username(username):
    return USER_RE.match(username)

def valid_password(psw):
    return PSW_RE.match(psw)

def valid_email(email):
    return EMAIL_RE.match(email)

def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)

def hash_str(s):
    return s + '|' + hmac.new(SECRET, s).hexdigest() # cookie format

def check_hash(h):
        s = h.split('|')[0]
        if h == hash_str(s):
                return s
        

class Login(webapp2.RequestHandler):
    def write_form(self, username='', error_m=''):
        template = JINJA_ENVIRONMENT.get_template('login.html')
        self.response.write(template.render({'username': username, 'error_m': error_m}))

    def get(self):
        self.write_form()
        
    def post(self):
        error_m = ''
        
        username = self.request.get('username')
        psw = self.request.get('password')
        
        username_OK = valid_username(username)
        psw_OK = valid_password(psw)
        if username_OK and psw_OK: 
            # verify if username & psw are correct in DB
            q = Account.query()
            q = q.filter(Account.username == username and Account.password == hash_str(psw).split('|')[1])
            account = q.fetch(1)
            if account:
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie', 'username=' + str(hash_str(username)) + '; Path=/')
                self.redirect('/')

        error_m = 'Invalid login'
        self.write_form(username, error_m)


class Logout(webapp2.RequestHandler):
    def get(self):
        # delete cookie (set to blank) and redirect to signup
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header('Set-Cookie', 'username=' + '; Path=/')
        self.redirect('/login')
        

class SignUp(webapp2.RequestHandler):
    def write_form(self, username='', email='', 
                   error_u='', error_p='', error_p2='', error_e=''):
        template = JINJA_ENVIRONMENT.get_template('signup.html')
        self.response.write(template.render({'username': username, 
                                        'email': email,
                                        'error_u': error_u,
                                        'error_p': error_p,
                                        'error_p2': error_p2,
                                        'error_e': error_e}))

    def get(self):
        self.write_form()
        
    def post(self):
        error_u = error_p = error_p2 = error_e = ''
        
        username = self.request.get('username')
        psw = self.request.get('password')
        psw2 = self.request.get('verify')
        email = self.request.get('email')
        
        username_OK = valid_username(username)
        if username_OK: 
            # verify if username already exists
            q = Account.query()
            q = q.filter(Account.username == username)
            account = q.fetch(1)
            if account:
                username_OK = False
                error_u = 'This username already exists!'

        psw_OK = valid_password(psw)
        psw2_OK = valid_password(psw2)
        if email == '':
            email_OK = True
        else:
            email_OK = valid_email(email)
        
        if username_OK and psw_OK and psw2_OK and (psw == psw2) and email_OK:
            # write new register in DB, hashing psw
            account = Account(username=username, password=hash_str(psw).split('|')[1], email=email)
            account.put()
            # prepare cookie & and redirect
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie', 'username=' + str(hash_str(username)) + '; Path=/')
            self.redirect('/')
        else: # prepare error msgs
            if not username_OK and error_u == '':
                error_u = 'That is not a valid username.'
                username = cgi.escape(username)
            if not psw_OK:
                error_p = 'That is not a valid password.'
            if not psw2_OK:
                error_p2 = 'That is not a valid password.'
            if psw_OK and psw2_OK and psw != psw2:
                error_p2 = "Your passwords didn't match."
            if not email_OK:
                error_e = 'That is not a valid email address.'
                email = cgi.escape(email)
            self.write_form(username, email, error_u, error_p, error_p2, error_e)


# Wiki handlers ------------------------------------------------------

def is_a_valid_username(wr):
    c = wr.request.cookies.get('username')
    valid_username = None
    if c: #valid_cookie(c):
        valid_username = check_hash(c)
    if not c or not valid_username:
        # invalid cookie - set cookie in header to null
        wr.response.headers['Content-Type'] = 'text/plain'
        wr.response.headers.add_header('Set-Cookie', 'username=' + '; Path=/')
    return valid_username


def display_page(wr, template, edit_mode, page_url, new_url, page_datetime=None):
    # get username from cookie
    valid_username = is_a_valid_username(wr)
    if not valid_username:
        wr.redirect('/login')          
    if not page_url:
        page_url = '/'
        
    pu = pc = ''
    if page_datetime: 
        page_key = WikiPage.query_wiki_datetime(valid_username, page_url, page_datetime)
    else:
        page_key = WikiPage.query_wiki(valid_username, page_url)
    page = page_key.get()
    if not page: # page does not exist
        if not edit_mode: # redirect to edit:
            wr.redirect(new_url)
    else:
        #pu, pc = page.page_url, page.content
        pu = page.page_url
        pc = page.content
    t = JINJA_ENVIRONMENT.get_template(template)
    wr.response.write(t.render(username = valid_username, edit_mode = edit_mode, 
                               page_url = pu, content = pc, error = ''))


class EditPage(webapp2.RequestHandler):
    def get(self, page_url):
        page_datetime = self.request.get('p') # get p parameter from querystring, only set if coming from 'history' page
        if DEBUG:
            d = '('+page_datetime+')'
            logging.info(d)
        display_page(self, 'edit-page.html', True, page_url, '', page_datetime)

    def post(self, page_url):
        valid_username = is_a_valid_username(self)
        if not valid_username:
            self.redirect('/login')          
        
        content = self.request.get('content')
        wp = WikiPage(username = valid_username, page_url = page_url, content = content)
        wp.put()
        time.sleep(1) # to avoid "eventual consistency" issues with datastore...
        self.redirect(page_url)


class ViewPage(webapp2.RequestHandler):
    def get(self, page_url):
        page_datetime = self.request.get('p') # get p parameter from querystring, only set if coming from 'history' page
        new_url = '/_edit{0}'.format(page_url)
        display_page(self, 'wikipage.html', False, page_url, new_url, page_datetime)
        

def history_page(wr, template, edit_mode, page_url):
    # get username from cookie
    valid_username = is_a_valid_username(wr)
    if not valid_username:
        wr.redirect('/login')          
    
    page_key = WikiPage.query_wiki(valid_username, page_url)
    page_list = page_key.fetch(50)
    if not page_list and not edit_mode: # page does not exist (should not happen)
        wr.redirect('/')

    t = JINJA_ENVIRONMENT.get_template(template)
    wr.response.write(t.render(username = valid_username, edit_mode = edit_mode, 
                               pages = page_list, page_url = page_url, error = ''))


class HistoryPage(webapp2.RequestHandler):
    def get(self, page_url):
        history_page(self, 'history.html', False, page_url)
        

class HomePage(webapp2.RequestHandler):
    def get(self):
        new_url = '/_edit/'
        display_page(self, 'wikipage.html', False, '/', new_url)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([ #('/', HomePage),
                               ('/signup', SignUp),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, ViewPage),
                               ],
                              debug=DEBUG)
