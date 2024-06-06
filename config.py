import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'my_secret_token'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT') or 'a_default_salt'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'kook051416@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'nhna pwqq lhbk cgro'