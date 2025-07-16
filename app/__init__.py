from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_cors import CORS
from flasgger import Swagger

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile('../config.py')
    db.init_app(app)
    CORS(app)

    from . import models
    Swagger(app)
    login_manager.init_app(app)
    from .routes import main_bp
    from .admin_routes import admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    return app
