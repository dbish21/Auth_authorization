import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-dev-key')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5433/feedback_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql:///feedback_test_db'
    WTF_CSRF_ENABLED = False 