#encoding=utf-8

# 载入配置文件 若配置文件不存在，则载入默认配置文件
try:
    import config
except ImportError:
    import config_default as config

import mdb


import bcrypt
import markdown
import unicodedata
import json
import datetime
import concurrent.futures
import pymysql
import os.path
import re
import subprocess
import tornado.escape
from tornado import gen
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web



from tornado.options import define, options

define("port", default=config.port, help="run on the given port", type=int)
define("mysql_host", default=config.mysql_host)
define("mysql_port", default=config.mysql_port, type=int)
define("mysql_database", default=config.mysql_database)
define("mysql_user", default=config.mysql_user)
define("mysql_password", default=config.mysql_password)

executor = concurrent.futures.ThreadPoolExecutor(2)

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/changepassword",ChangePasswordHandler),
            (r"/createproject",CreateProjectHandler),
            (r"/login", LoginHandler),
            (r"/logout",LogoutHandler),
            (r"/myprojects",MyProjectsHandler),
            (r"/projects",ProjectsHandler),
            (r"/register",RegisterHandler),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/login",
            debug=True,
        )
        super(Application, self).__init__(handlers, **settings)

        self.db=mdb.Connection(
            host=options.mysql_host,
            user=options.mysql_user,
            password=options.mysql_password,
            port=options.mysql_port,
            db=options.mysql_database,
            charset='utf8',
            #cursorclass=pymysql.cursors.DictCursor
        )

    



class BaseHandler(tornado.web.RequestHandler):
    def prepare(self):
        self.data={}
        self.data['error']=None
        self.data['success']=None
        self.data['next']=self.get_argument('next',None)

    @property
    def db(self):
        return self.application.db

    def assign(self,k,v):
        self.data[k]=v

    def get_current_user(self):
        user_id=self.get_secure_cookie("eq_user")
        if not user_id: return None

        sql='select * from eq_users where id=%s'
        row=self.db.get(sql,int(user_id))

        return row




class HomeHandler(BaseHandler):
    """
    主页
    """
    def get(self):

        sql='select * from eq_projects where enable=1 order by id desc limit 0,3'
        rows=self.db.query(sql)
        
        self.assign('projects',rows)
        self.render('home.html',data=self.data)

class ProjectsHandler(BaseHandler):
    """
    问卷列表
    """
    def get(self):

        sql='select * from eq_projects where enable=1 order by id desc'
        rows=self.db.query(sql)
        
        self.assign('projects',rows)
        self.render('projects.html',data=self.data)


class MyProjectsHandler(BaseHandler):
    """
    我的问卷
    """
    @tornado.web.authenticated
    def get(self):
        user=self.get_current_user()

        sql="select * from eq_projects where userid=%s"
        projects=self.db.query(sql,user.id)

        self.assign('projects',projects)
        self.render('myprojects.html',data=self.data)


class CreateProjectHandler(BaseHandler):
    """
    创建问卷
    """
    @tornado.web.authenticated
    def get(self):
        sql="select * from eq_fieldtypes where enable=1 order by `order`"
        fieldtypes=self.db.query(sql)

        self.assign('fieldtypes',fieldtypes)
        self.render('createproject.html',data=self.data)



class RegisterHandler(BaseHandler):
    """
    注册
    """

    def get(self):
        self.render('register.html',data=self.data)
    
    @gen.coroutine
    def post(self):

        sql="select * from eq_users where username=%s"
        user=self.db.get(sql,self.get_argument('username'))

        if user:
            self.data['error']="该用户名已被占用"
            self.render('register.html',data=self.data)
            return
        
        if self.get_argument('password')!=self.get_argument('password2'):
            self.data['error']="两次密码不一致"
            self.render('register.html',data=self.data)
            return

        password=yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            bcrypt.gensalt()
        )

        sql="insert into eq_users (username,password) values (%s,%s)"
        self.db.execute(sql,self.get_argument('username'),password)
        
        self.redirect(self.get_argument("next","/login"))



class LoginHandler(BaseHandler):
    """
    登录
    """

    def get(self):
        self.render('login.html',data=self.data)
    
    @gen.coroutine
    def post(self):
        sql="select * from eq_users where username=%s"
        user=self.db.get(sql,self.get_argument('username'))
        if not user:
            self.data['error']="用户名错误"
            self.render('login.html',data=self.data)
            return

        password=yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(user['password'])
        )

        if password==tornado.escape.utf8(user['password']):
            self.set_secure_cookie('eq_user',str(user['id']))
            self.redirect(self.get_argument('next','/myprojects'))
        else:
            self.data['error']="密码错误"
            self.render('login.html',data=self.data)
            return

        


class LogoutHandler(BaseHandler):
    """
    注销
    """
    def get(self):
        self.clear_cookie('eq_user')
        self.redirect(self.get_argument("next",'/login'))


class ChangePasswordHandler(BaseHandler):
    """
    修改密码
    """

    @tornado.web.authenticated
    def get(self):
        self.render('changepassword.html',data=self.data)
        user_id=self.get_current_user().id

    @tornado.web.authenticated
    @gen.coroutine
    def post(self):


        user=self.get_current_user()

        password=yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("password")),
            tornado.escape.utf8(user['password'])
        )

        if password!=tornado.escape.utf8(user['password']):
            self.data['error']="原密码错误"
            self.render('changepassword.html',data=self.data)
            return

        if self.get_argument("npassword")!=self.get_argument("npasswordr"):
            self.data['error']="新密码不一致"
            self.render('changepassword.html',data=self.data)
            return

        password=yield executor.submit(
            bcrypt.hashpw, tornado.escape.utf8(self.get_argument("npassword")),
            bcrypt.gensalt()
        )

        sql="update eq_users set password=%s where id=%s"
        self.db.execute(sql,password,user.id)


        self.data['success']="密码修改成功"
        self.render('changepassword.html',data=self.data)




class DateEncoder(json.JSONEncoder):  
    def default(self, obj):  
        if isinstance(obj, datetime.datetime):  
            return obj.strftime('%Y-%m-%d %H:%M:%S')  
        elif isinstance(obj, date):  
            return obj.strftime("%Y-%m-%d")  
        else:  
            return json.JSONEncoder.default(self, obj) 


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == "__main__":
    main()
