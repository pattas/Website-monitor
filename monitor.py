import time
import requests
import sqlalchemy as sa
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from typing import Optional
from app import app, db
from app.models import MonitoredURL, MonitoringLog
from app.checks import run_advanced_checks_for_url

def check_url(url_to_check: MonitoredURL):
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

def run_monitoring():
    """Fetches URLs, runs standard checks, and occasionally advanced checks."""
    now = datetime.now(timezone.utc)
    print(f"[{now}] Starting monitoring run...")
    urls_checked_advanced = 0

    with app.app_context():
        urls_to_check = db.session.scalars(sa.select(MonitoredURL)).all()
        print(f"Found {len(urls_to_check)} URLs to monitor.")

        logs_to_add = []
        urls_updated_advanced = [] # Track URLs whose advanced info was updated

        for url_obj in urls_to_check:
            # --- Standard Check --- (Run every time)
            print(f"Checking {url_obj.url}...")
            log_entry = check_url(url_obj)
            logs_to_add.append(log_entry)

            # --- Advanced Check --- (Run less frequently, e.g., once a day)
            should_run_adv_check = False
            if url_obj.last_advanced_check is None:
                should_run_adv_check = True
            else:
                # Ensure comparison is between naive datetimes (assuming both represent UTC)
                time_since_last_check = now.replace(tzinfo=None) - url_obj.last_advanced_check
                if time_since_last_check > timedelta(hours=23): # Run approx every 24 hours
                    should_run_adv_check = True

            if should_run_adv_check:
                try:
                    # Call the function from app.checks
                    updated = run_advanced_checks_for_url(url_obj)
                    if updated:
                        urls_updated_advanced.append(url_obj) # Mark if data actually changed
                    urls_checked_advanced += 1
                    time.sleep(1) # Add delay after advanced check
                except Exception as e:
                     print(f"!! Error during advanced check for {url_obj.url}: {e}")
            else:
                 time.sleep(0.2) # Shorter delay for standard checks only

        # --- Commit Changes ---
        if logs_to_add:
            db.session.add_all(logs_to_add)
            print(f"Adding {len(logs_to_add)} log entries.")

        # Only commit if there are new logs or if advanced checks updated data
        if logs_to_add or urls_updated_advanced:
            try:
                db.session.commit()
                print("Committed logs and/or advanced check updates.")
            except Exception as e:
                print(f"Error committing session: {e}")
                db.session.rollback()
        else:
            print("No new logs or updates to commit.")

    print(f"[{datetime.now(timezone.utc)}] Monitoring run finished. Advanced checks run for {urls_checked_advanced} URLs.")

if __name__ == '__main__':
    standard_interval = 5
    while True:
        run_monitoring()
        print(f"Sleeping for {standard_interval} seconds...")
        time.sleep(standard_interval)
