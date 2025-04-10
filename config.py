import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
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
