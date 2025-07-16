import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'your-secret-key'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # максимум 16 МБ на файл
