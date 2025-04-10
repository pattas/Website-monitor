import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
import sqlalchemy as sa # Needed for querying URLs

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

# Initialize APScheduler
scheduler = BackgroundScheduler(
    jobstores=app.config['SCHEDULER_JOBSTORES'],
    executors=app.config['SCHEDULER_EXECUTORS'],
    job_defaults=app.config['SCHEDULER_JOB_DEFAULTS'],
    timezone=timezone.utc # Use UTC for scheduling
)

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

# Import models and tasks *after* db and app are defined, but *before* scheduling logic
from app import models, tasks

# --- Logging Setup ---
if not app.debug and not app.testing: # Only configure file logging when not in debug/testing
    if not os.path.exists('logs'):
        os.mkdir('logs')
    # Use RotatingFileHandler to limit log file size
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    # Define log format
    log_format = '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    file_handler.setFormatter(logging.Formatter(log_format))
    # Set logging level (e.g., INFO, WARNING, ERROR, DEBUG)
    file_handler.setLevel(logging.INFO)
    # Remove default Flask handler if exists
    app.logger.handlers.clear()
    # Add our file handler
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

def schedule_initial_jobs(app_context):
    """Schedules jobs for all existing MonitoredURLs."""
    app.logger.info("Attempting to schedule initial jobs...")
    try:
        with app_context:
            app.logger.debug("Inside app_context for initial job scheduling.")
            urls = db.session.scalars(sa.select(models.MonitoredURL)).all()
            app.logger.info(f"Found {len(urls)} URLs in the database for initial scheduling.")
            if not urls:
                app.logger.info("No URLs found to schedule.")
                return

            for url in urls:
                app.logger.debug(f"Processing URL ID: {url.id}, URL: {url.url}")
                # Schedule standard check (e.g., every 5 seconds)
                job_id_standard = f'check_url_{url.id}'
            if not scheduler.get_job(job_id_standard):
                scheduler.add_job(
                    func=tasks.run_single_url_check,
                    trigger='interval',
                    seconds=5, # Changed from minutes=5
                    id=job_id_standard,
                    args=[url.id],
                    replace_existing=True,
                    misfire_grace_time=60 # Allow 1 minute delay before misfire
                )
                app.logger.info(f"Scheduled standard check job '{job_id_standard}' for URL ID {url.id}")
            else:
                app.logger.debug(f"Standard check job '{job_id_standard}' already exists for URL ID {url.id}")

            # Schedule advanced check (e.g., every 24 hours)
            job_id_advanced = f'advanced_check_url_{url.id}'
            if not scheduler.get_job(job_id_advanced):
                scheduler.add_job(
                    func=tasks.run_single_url_advanced_check,
                    trigger='interval',
                    hours=24, # Adjust interval as needed
                    id=job_id_advanced,
                    args=[url.id],
                    replace_existing=True,
                    misfire_grace_time=3600 # Allow 1 hour delay
                )
                app.logger.info(f"Scheduled advanced check job '{job_id_advanced}' for URL ID {url.id}")
            else:
                app.logger.debug(f"Recurring advanced check job '{job_id_advanced}' already exists for URL ID {url.id}")

            # Also schedule an immediate initial run if it hasn't happened
            # Note: A 'date' trigger job normally runs once and is removed.
            # We add it here to ensure data is populated on first start after adding this code.
            # Subsequent starts won't re-add it if the recurring job exists (or if the db stores the job).
            # A better approach might be to check url.last_advanced_check, but this is simpler for now.
            job_id_initial_advanced = f'advanced_check_url_{url.id}_initial'
            # Removed 'and not url.last_advanced_check' to ensure it tries to schedule once after code update
            if not scheduler.get_job(job_id_initial_advanced):
                 try:
                     app.logger.debug(f"Attempting to schedule initial immediate advanced check job '{job_id_initial_advanced}' for URL ID {url.id}")
                     scheduler.add_job(
                         func=tasks.run_single_url_advanced_check,
                         trigger='date', # Run immediately
                         id=job_id_initial_advanced,
                         args=[url.id]
                         # No replace_existing needed for date jobs usually
                     )
                     app.logger.info(f"Scheduled initial immediate advanced check job '{job_id_initial_advanced}' for URL ID {url.id}")
                 except Exception as e_initial:
                     app.logger.error(f"Error scheduling initial immediate advanced check for {url.id}: {e_initial}", exc_info=True)


        app.logger.debug("Finished iterating through URLs for initial scheduling.")
    except Exception as e:
        app.logger.error(f"Error during initial job scheduling: {e}", exc_info=True)

# Start the scheduler only if it's not already running (e.g., in dev mode with reloader)
if not scheduler.running:
    scheduler.start()
    app.logger.info("Scheduler started.")
    # Schedule jobs for existing URLs after scheduler starts
    schedule_initial_jobs(app.app_context())


# Import routes *after* app, db, login, scheduler are initialized
from app import routes
