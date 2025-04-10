import time
import requests
import sqlalchemy as sa
from datetime import datetime, timezone
from app import app, db # Import app for logger
from app.models import MonitoredURL, MonitoringLog
from app.checks import run_advanced_checks_for_url
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Tuple

def check_url(url_to_check: MonitoredURL) -> MonitoringLog:
    """Checks a single URL status/response and returns a MonitoringLog object."""
    log = MonitoringLog(monitored_url_id=url_to_check.id)
    try:
        start_time = time.time()
        # Allow redirects, verify SSL by default
        response = requests.get(url_to_check.url, timeout=10, allow_redirects=True, verify=True)
        end_time = time.time()
        log.status_code = response.status_code
        log.response_time_ms = round((end_time - start_time) * 1000, 2)
    except requests.exceptions.Timeout:
        log.error_message = "Request timed out"
    except requests.exceptions.SSLError as e:
        log.error_message = f"SSL Error: {str(e)[:150]}"
    except requests.exceptions.ConnectionError as e:
         log.error_message = f"Connection Error: {str(e)[:150]}"
    except requests.exceptions.RequestException as e:
        log.error_message = f"Request failed: {str(e)[:150]}"
    except Exception as e:
        log.error_message = f"Unexpected error: {str(e)[:150]}"

    # Always set status/response time to None if an error occurred before getting response
    if log.error_message:
        log.status_code = None
        log.response_time_ms = None

    log.timestamp = datetime.now(timezone.utc)
    return log

def check_url_batch(url_obj: MonitoredURL) -> Tuple[MonitoredURL, Optional[MonitoringLog]]:
    """Wrapper function for batch processing that returns both the URL object and its log."""
    try:
        log = check_url(url_obj)
        return url_obj, log
    except Exception as e:
        app.logger.error(f"Error checking URL {url_obj.url} (ID: {url_obj.id}): {e}", exc_info=True)
        return url_obj, None

def run_batch_url_checks(max_workers: int = 5):
    """Task function to check all URLs in batches using a thread pool."""
    with app.app_context():
        # Get all URLs to check
        urls = db.session.scalars(sa.select(MonitoredURL)).all()
        if not urls:
            app.logger.debug("No URLs found for batch check.")
            return
        
        app.logger.info(f"Starting batch check for {len(urls)} URLs with {max_workers} workers")
        results = []
        
        # Use ThreadPoolExecutor to check URLs in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all URL checks to the thread pool
            future_to_url = {executor.submit(check_url_batch, url): url for url in urls}
            
            # Process results as they complete
            for future in future_to_url:
                try:
                    url_obj, log = future.result()
                    if log:
                        results.append(log)
                except Exception as e:
                    app.logger.error(f"Exception processing URL check result: {e}", exc_info=True)
        
        # Save all logs in a single transaction
        if results:
            try:
                db.session.add_all(results)
                db.session.commit()
                app.logger.info(f"Saved {len(results)} logs from batch check")
            except Exception as e:
                app.logger.error(f"Failed to commit logs from batch check: {e}", exc_info=True)
                db.session.rollback()

def run_single_url_check(url_id: int):
    """Task function to check a single URL and save the log."""
    with app.app_context():
        url_obj = db.session.get(MonitoredURL, url_id)
        if not url_obj:
            app.logger.error(f"URL with ID {url_id} not found for standard check.")
            return

        app.logger.debug(f"Running standard check for {url_obj.url} (ID: {url_id})")
        log_entry = check_url(url_obj)
        db.session.add(log_entry)
        try:
            db.session.commit()
            app.logger.debug(f"Log saved for {url_obj.url} (ID: {url_id})")
        except Exception as e:
            app.logger.error(f"Failed to commit log for {url_obj.url} (ID: {url_id}): {e}", exc_info=True)
            db.session.rollback()

def run_single_url_advanced_check(url_id: int):
    """Task function to run advanced checks (SSL/Domain) for a single URL."""
    app.logger.info(f"Starting advanced check task for URL ID {url_id}")
    try:
        with app.app_context():
            app.logger.debug(f"Advanced check task for URL ID {url_id}: Entered app_context.")
            url_obj = db.session.get(MonitoredURL, url_id)
            if not url_obj:
                app.logger.error(f"Advanced check task for URL ID {url_id}: URL not found.")
                return

            app.logger.debug(f"Advanced check task for URL ID {url_id}: Found URL: {url_obj.url}. Proceeding with check.")
            try:
                # Call the check function which now updates the timestamp itself
                app.logger.debug(f"Advanced check task for URL ID {url_id}: Calling run_advanced_checks_for_url...")
                updated = run_advanced_checks_for_url(url_obj) # This function now uses logging too
                app.logger.debug(f"Advanced check task for URL ID {url_id}: run_advanced_checks_for_url completed. Result (updated={updated}).")

                # The check function now handles setting url_obj.last_advanced_check
                # We just need to commit the session to save changes (expiry dates AND timestamp)
                app.logger.debug(f"Advanced check task for URL ID {url_id}: Attempting to commit session...")
                db.session.commit()
                app.logger.info(f"Advanced check task for URL ID {url_id}: Session committed successfully.")

            except Exception as e_inner:
                app.logger.error(f"Advanced check task for URL ID {url_id}: Error during check execution or commit for {url_obj.url}: {e_inner}", exc_info=True)
                db.session.rollback()
                app.logger.debug(f"Advanced check task for URL ID {url_id}: Session rolled back due to error.")

    except Exception as e_outer:
        # Catch errors happening outside the app_context or during context setup
        app.logger.error(f"Advanced check task for URL ID {url_id}: Outer exception during task execution: {e_outer}", exc_info=True)
