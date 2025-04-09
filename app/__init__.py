import os
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from datetime import datetime, timezone, timedelta

# Determine the absolute path to the directory containing this file (__init__.py)
basedir = os.path.abspath(os.path.dirname(__file__))
# Determine the absolute path to the project root (one level up from 'app')
project_root = os.path.dirname(basedir)
# Determine the absolute path to the templates directory
template_dir = os.path.join(project_root, 'templates')
# Determine the absolute path to the static directory
static_dir = os.path.join(project_root, 'static')

# Explicitly provide template_folder and static_folder using absolute paths
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login' # Function name for the login route

@app.context_processor
def inject_utilities():
    return {
        'now': datetime.utcnow,
        'timedelta': timedelta # Make timedelta available
    }

# Custom filter for getting timezone-aware now() in UTC
@app.template_filter('utc')
def utcnow_filter(dt):
    """Assumes input is naive UTC datetime, returns offset-aware UTC."""
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=timezone.utc)
    return dt # Return original if not a datetime

from app import routes, models
