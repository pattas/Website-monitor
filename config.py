import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("No SECRET_KEY set for Flask application. Please set it in the .env file.")
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # APScheduler Configuration
    SCHEDULER_JOBSTORES = {
        'default': {'type': 'sqlalchemy', 'url': SQLALCHEMY_DATABASE_URI}
    }
    SCHEDULER_EXECUTORS = {
        'default': {'type': 'threadpool', 'max_workers': 10} # Adjust max_workers as needed
    }
    SCHEDULER_JOB_DEFAULTS = {
        'coalesce': False, # Run missed jobs? Maybe True is better? Let's start with False.
        'max_instances': 3 # Max concurrent instances of a job
    }
    SCHEDULER_API_ENABLED = True # Optional: enables a Flask endpoint for scheduler info

    # Monitoring Configuration
    STANDARD_CHECK_INTERVAL_SECONDS = int(os.environ.get('STANDARD_CHECK_INTERVAL_SECONDS', 60)) # Default: 60 seconds
    ADVANCED_CHECK_INTERVAL_HOURS = int(os.environ.get('ADVANCED_CHECK_INTERVAL_HOURS', 24)) # Default: 24 hours
