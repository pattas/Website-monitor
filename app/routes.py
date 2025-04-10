from flask import render_template, flash, redirect, url_for, request, jsonify, make_response
from flask_login import current_user, login_user, logout_user, login_required
import sqlalchemy as sa
from app import app, db, scheduler # Import app for logger
from app import tasks # Import tasks module
from app.forms import LoginForm, RegistrationForm, AddURLForm, DeleteURLForm, RunFullScanForm
from app.models import User, MonitoredURL, MonitoringLog
from urllib.parse import urlsplit, urlparse
from apscheduler.jobstores.base import JobLookupError # Import JobLookupError
from datetime import datetime, timedelta, timezone
from sqlalchemy import desc
from app.checks import run_advanced_checks_for_url, get_ip_address, get_rdap_info, get_dns_records, run_traceroute
import json # For pretty printing RDAP
from weasyprint import HTML, CSS # Import WeasyPrint


# --- Helper Functions ---

def _calculate_uptime_stats(url_id: int, start_time: datetime):
    """Helper function to calculate uptime percentage, success count, and total count."""
    logs_in_period = db.session.scalars(
        sa.select(MonitoringLog)
        .where(
            MonitoringLog.monitored_url_id == url_id,
            MonitoringLog.timestamp >= start_time
        )
    ).all()

    total_checks = len(logs_in_period)
    successful_checks = 0
    for log in logs_in_period:
        # Consider successful if status code is 2xx
        if log.status_code and log.status_code >= 200 and log.status_code < 300:
            successful_checks += 1

    uptime_percentage = (successful_checks / total_checks * 100) if total_checks > 0 else 100.0 # Assume 100% if no checks?
    return uptime_percentage, successful_checks, total_checks

def _get_url_details_context(url_id: int, url_obj: MonitoredURL = None):
    """Helper function to fetch and prepare context data for the url_details template."""
    if url_obj is None:
        url_obj = db.session.get(MonitoredURL, url_id)
        if url_obj is None:
            return None # Indicate URL not found

    # Fetch latest log for current status
    latest_log = db.session.scalars(
        sa.select(MonitoringLog)
        .where(MonitoringLog.monitored_url_id == url_id)
        .order_by(MonitoringLog.timestamp.desc())
        .limit(1)
    ).first()

    # Determine current status string
    current_status = "UNKNOWN"
    if latest_log:
        if latest_log.status_code and latest_log.status_code >= 200 and latest_log.status_code < 300:
            current_status = "OK"
        elif latest_log.status_code:
            current_status = "WARN"
        else:
            current_status = "ERROR"

    # --- Uptime Calculation ---
    now = datetime.now(timezone.utc)
    time_24h_ago = now - timedelta(hours=24)
    time_7d_ago = now - timedelta(days=7)
    uptime_24h, successful_checks_24h, total_checks_24h = _calculate_uptime_stats(url_id, time_24h_ago)
    uptime_7d, successful_checks_7d, total_checks_7d = _calculate_uptime_stats(url_id, time_7d_ago)

    # --- Fetch Recent History ---
    history_logs = db.session.scalars(
        sa.select(MonitoringLog)
        .where(MonitoringLog.monitored_url_id == url_id)
        .order_by(MonitoringLog.timestamp.desc())
        .limit(50) # Limit the number of history logs displayed
    ).all()

    # --- Prepare Scan Results ---
    scan_results_dict = None
    if url_obj.last_full_scan:
        try:
            dns_data = json.loads(url_obj.last_scan_dns) if url_obj.last_scan_dns else None
        except json.JSONDecodeError:
            app.logger.warning(f"Failed to parse stored DNS JSON for URL ID {url_id}")
            dns_data = {"error": "Failed to parse stored data"}

        try:
            # Also parse RDAP data if available
            # Pass the raw JSON string directly to the template.
            # The <pre> tag will handle displaying it.
            # No need to parse it here.
            rdap_data_string = url_obj.last_scan_rdap
        except Exception as e:
             # Catch potential errors reading the attribute, though unlikely
             app.logger.error(f"Error accessing RDAP data string for URL ID {url_id}: {e}")
             rdap_data_string = 'Error retrieving stored RDAP data.'


        scan_results_dict = {
            'ip_address': url_obj.last_scan_ip,
            'rdap': rdap_data_string, # Pass the raw string
            'dns': dns_data, # Keep DNS parsed for potential iteration in template if needed elsewhere
            'traceroute': url_obj.last_scan_traceroute
        }

    return {
        'title': f"Details for {url_obj.name or url_obj.url}",
        'url': url_obj,
        'latest_log': latest_log,
        'current_status': current_status,
        'uptime_24h': uptime_24h,
        'successful_checks_24h': successful_checks_24h,
        'total_checks_24h': total_checks_24h,
        'uptime_7d': uptime_7d,
        'successful_checks_7d': successful_checks_7d,
        'total_checks_7d': total_checks_7d,
        'history_logs': history_logs,
        'scan_results': scan_results_dict
    }

# Helper function to safely parse stored JSON
def parse_json_string(json_string, logger):
    if not json_string:
        return None
    try:
        return json.loads(json_string)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse stored JSON: {json_string[:100]}..." ) # Log snippet
        return None # Or return the raw string if preferred


# --- Routes ---

@app.route('/')
@app.route('/index')
@login_required
def index():
    # Redirect to dashboard if logged in
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    form = AddURLForm()
    # Fetch URLs monitored by the current user
    urls_query = sa.select(MonitoredURL).where(MonitoredURL.user_id == current_user.id).order_by(MonitoredURL.added_at.desc())
    user_urls = db.session.scalars(urls_query).all()

    # Fetch the latest log for each URL to display status and create delete forms
    urls_with_status = []
    delete_forms = {}
    for url in user_urls:
        latest_log = db.session.scalars(
            sa.select(MonitoringLog)
            .where(MonitoringLog.monitored_url_id == url.id)
            .order_by(MonitoringLog.timestamp.desc())
            .limit(1)
        ).first()
        urls_with_status.append({'url': url, 'latest_log': latest_log})
        delete_forms[url.id] = DeleteURLForm(prefix=f"delete_{url.id}")

    return render_template('dashboard.html', title='Dashboard', form=form, 
                          urls_with_status=urls_with_status, delete_forms=delete_forms)

@app.route('/add_url', methods=['POST'])
@login_required
def add_url():
    form = AddURLForm()
    if form.validate_on_submit():
        # Check if URL already exists for this user
        existing_url = db.session.scalar(sa.select(MonitoredURL).where(
            MonitoredURL.user_id == current_user.id, MonitoredURL.url == form.url.data))
        if existing_url:
            flash('You are already monitoring this URL.')
        else:
            new_url = MonitoredURL(url=form.url.data, name=form.name.data, owner=current_user)
            db.session.add(new_url)
            db.session.commit() # Commit to get the new_url.id

            # Schedule advanced check jobs for the new URL
            # (Standard checks are handled by the batch job)
            try:
                job_id_advanced = f'advanced_check_url_{new_url.id}'
                scheduler.add_job(
                    func=tasks.run_single_url_advanced_check,
                    trigger='interval',
                    hours=app.config['ADVANCED_CHECK_INTERVAL_HOURS'], # Use config value
                    id=job_id_advanced,
                    args=[new_url.id],
                    replace_existing=True,
                    misfire_grace_time=3600
                )
                app.logger.info(f"Scheduled recurring advanced check for new URL {new_url.url} (ID: {new_url.id})")

                # Also schedule an immediate initial advanced check
                job_id_initial_advanced = f'advanced_check_url_{new_url.id}_initial'
                scheduler.add_job(
                    func=tasks.run_single_url_advanced_check,
                    trigger='date', # Run immediately
                    id=job_id_initial_advanced,
                    args=[new_url.id]
                )
                app.logger.info(f"Scheduled initial immediate advanced check for new URL {new_url.url} (ID: {new_url.id})")

                # Also run an immediate standard check
                tasks.run_single_url_check(new_url.id)
                app.logger.info(f"Executed immediate standard check for new URL {new_url.url} (ID: {new_url.id})")

                flash('URL added and monitoring scheduled successfully!')
            except Exception as e:
                app.logger.error(f"Error scheduling jobs for new URL {new_url.id}: {e}", exc_info=True)
                flash('URL added, but failed to schedule monitoring tasks. Please check logs.', 'warning')
    else:
        # Handle form errors (e.g., invalid URL)
        for field, errors in form.errors.items():
            for error in errors:
                 flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/delete_url/<int:url_id>', methods=['POST']) # Changed to POST only
@login_required
def delete_url(url_id):
    url_to_delete = db.session.get(MonitoredURL, url_id)
    if url_to_delete is None:
        flash('URL not found.', 'warning')
        return redirect(url_for('dashboard'))
    if url_to_delete.owner != current_user:
        flash('You do not have permission to delete this URL.', 'danger')
        return redirect(url_for('dashboard'))

    # Remove scheduled jobs before deleting the URL
    # Only need to remove advanced check jobs since standard checks are handled by batch job
    job_id_advanced = f'advanced_check_url_{url_id}'

    try:
        scheduler.remove_job(job_id_advanced)
        app.logger.info(f"Removed advanced check job {job_id_advanced} for URL ID {url_id}")
    except JobLookupError:
        app.logger.warning(f"Recurring advanced check job {job_id_advanced} not found for URL ID {url_id}, skipping removal.")
    except Exception as e:
        app.logger.error(f"Error removing recurring job {job_id_advanced} for URL ID {url_id}: {e}", exc_info=True)
        flash('Error removing recurring advanced monitoring task. Please check logs.', 'warning')

    # Attempt to remove the initial job as well (it might have run and been removed already)
    job_id_initial_advanced = f'advanced_check_url_{url_id}_initial'
    try:
        scheduler.remove_job(job_id_initial_advanced)
        app.logger.info(f"Removed initial advanced check job {job_id_initial_advanced} for URL ID {url_id}")
    except JobLookupError:
        # This is expected if the job already ran
        app.logger.debug(f"Initial advanced check job {job_id_initial_advanced} not found for URL ID {url_id} (likely already run), skipping removal.")
    except Exception as e:
        app.logger.error(f"Error removing initial job {job_id_initial_advanced} for URL ID {url_id}: {e}", exc_info=True)
        # Don't necessarily flash an error here, as it might be expected to fail

    # Cascade delete will handle the logs automatically due to model definition
    # Delete associated logs first (No longer needed)
    # logs_to_delete = db.session.scalars(sa.select(MonitoringLog).where(MonitoringLog.monitored_url_id == url_id)).all()
    # for log in logs_to_delete:
    #     db.session.delete(log)

    # Now delete the URL object itself
    db.session.delete(url_to_delete)
    db.session.commit() # Commit the change (deleting the URL)
    flash('URL deleted successfully.') # Simplified message
    return redirect(url_for('dashboard'))

@app.route('/url_details/<int:url_id>')
@login_required
def view_url_details(url_id):
    # Fetch URL and ensure ownership first
    url_obj = db.session.get(MonitoredURL, url_id)
    if url_obj is None or url_obj.owner != current_user:
        flash('URL not found or you do not have permission to view it.', 'warning')
        return redirect(url_for('dashboard'))

    # Get context data using the helper function
    context = _get_url_details_context(url_id, url_obj)
    if context is None: # Should not happen if initial check passed, but good practice
        flash('URL not found.', 'warning')
        return redirect(url_for('dashboard'))

    # Instantiate the form for the "Run Full Scan" button
    run_scan_form = RunFullScanForm()

    # Add the form to the context
    context['run_scan_form'] = run_scan_form

    return render_template('url_details.html', **context)

@app.route('/api/monitoring_data')
@login_required
def monitoring_data():
    """API endpoint to provide data for the monitoring chart.

    Fetches logs only from the last 24 hours.
    """
    # Fetch URLs for the current user
    user_urls_query = sa.select(MonitoredURL.id).where(MonitoredURL.user_id == current_user.id)
    user_url_ids = db.session.scalars(user_urls_query).all()

    if not user_url_ids:
        return jsonify({'labels': [], 'datasets': []})

    # Calculate the time 24 hours ago
    time_threshold = datetime.now(timezone.utc) - timedelta(hours=24)

    # Fetch logs for user's URLs within the last 24 hours
    logs_query = (
        sa.select(MonitoringLog.timestamp, MonitoringLog.response_time_ms, MonitoredURL.url, MonitoredURL.name)
        .join(MonitoredURL)
        .where(
            MonitoringLog.monitored_url_id.in_(user_url_ids),
            MonitoringLog.timestamp >= time_threshold # Filter by time
        )
        .order_by(MonitoringLog.timestamp.asc())
    )
    logs = db.session.execute(logs_query).all()

    datasets = {}
    labels = set()

    for log in logs:
        label = log.name if log.name else log.url
        # Convert timestamp to a consistent format for Chart.js time scale
        # ISO 8601 format is generally well-supported
        timestamp_iso = log.timestamp.isoformat()
        labels.add(timestamp_iso)

        if label not in datasets:
            datasets[label] = {
                'label': label,
                'data': {},
                'borderColor': f'hsl({hash(label) % 360}, 70%, 50%)', # Basic color generation
                'tension': 0.3, # Use smoother lines value from template
                'fill': False
            }
        datasets[label]['data'][timestamp_iso] = log.response_time_ms if log.response_time_ms is not None else None # Use null for Chart.js spanGaps

    # Prepare data for Chart.js (logic largely remains the same, uses ISO timestamps)
    sorted_labels = sorted(list(labels))
    chart_datasets = []
    for ds_label, ds_config in datasets.items():
        # Map data points to the sorted labels, ensuring correct time alignment
        data_points = [ds_config['data'].get(lbl) for lbl in sorted_labels]
        chart_datasets.append({
            'label': ds_config['label'],
            'data': data_points,
            'borderColor': ds_config['borderColor'],
            'tension': ds_config['tension'],
            'fill': ds_config['fill'],
            'spanGaps': True # Connect lines over missing points (null)
        })

    # Return labels as ISO strings, Chart.js time scale will handle them
    return jsonify({'labels': sorted_labels, 'datasets': chart_datasets})

@app.route('/api/monitoring_data/<int:url_id>')
@login_required
def monitoring_data_single(url_id):
    """API endpoint to provide data for the detail chart for a single URL."""
    # Fetch the specific URL and ensure ownership
    url = db.session.get(MonitoredURL, url_id)
    if url is None or url.owner != current_user:
        return jsonify({'error': 'URL not found or permission denied'}), 404

    # Calculate the time 24 hours ago
    time_threshold = datetime.now(timezone.utc) - timedelta(hours=24)

    # Fetch logs for this specific URL within the last 24 hours
    logs_query = (
        sa.select(MonitoringLog.timestamp, MonitoringLog.response_time_ms)
        .where(
            MonitoringLog.monitored_url_id == url_id,
            MonitoringLog.timestamp >= time_threshold
        )
        .order_by(MonitoringLog.timestamp.asc())
    )
    logs = db.session.execute(logs_query).all()

    labels = []
    data_points = []
    for log in logs:
        labels.append(log.timestamp.isoformat()) # ISO format for time scale
        data_points.append(log.response_time_ms if log.response_time_ms is not None else None) # Null for gaps

    chart_data = {
        'labels': labels,
        'datasets': [{
            'label': 'Response Time (ms)',
            'data': data_points,
            'borderColor': 'rgb(75, 192, 192)', # Example color
            'backgroundColor': 'rgba(75, 192, 192, 0.5)',
            'tension': 0.3,
            'fill': False,
            'spanGaps': True
        }]
    }

    return jsonify(chart_data)

@app.route('/trigger_advanced_check/<int:url_id>', methods=['POST'])
@login_required
def trigger_advanced_check(url_id):
    """Manually triggers the SSL and WHOIS check for a specific URL."""
    url = db.session.get(MonitoredURL, url_id)
    if url is None or url.owner != current_user:
        flash('URL not found or permission denied.', 'danger')
        return redirect(url_for('dashboard'))

    now = datetime.now(timezone.utc)
    # Check if last check was recent (e.g., within 23 hours) - Compare aware times
    if url.last_advanced_check and (now - url.last_advanced_check) < timedelta(hours=23):
        time_since_last = now - url.last_advanced_check
        hours_since = time_since_last.total_seconds() / 3600
        flash(f'Advanced check already run recently ({hours_since:.1f} hours ago). Please wait.', 'warning')
        return redirect(url_for('view_url_details', url_id=url_id))

    try:
        app.logger.info(f"Manual trigger for advanced checks on {url.url} (ID: {url_id}) by user {current_user.username}")
        updated = run_advanced_checks_for_url(url)
        if updated:
            db.session.commit()
            flash('Advanced check completed and data updated.', 'success')
        else:
             # If updated is False, it means either the check failed or the data didn't change
             # We still update last_advanced_check time if the check itself ran without fundamental errors
             if url.last_advanced_check is None or (now - url.last_advanced_check) > timedelta(minutes=5):
                 url.last_advanced_check = now
                 db.session.commit()
             flash('Advanced check completed. No changes detected or check failed (see logs).', 'info')

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error during manual advanced check trigger for URL ID {url_id}: {e}", exc_info=True)
        flash('An error occurred while running the advanced check.', 'danger')

    return redirect(url_for('view_url_details', url_id=url_id))

@app.route('/run_full_scan/<int:url_id>', methods=['POST'])
@login_required
def run_full_scan(url_id):
    """Runs RDAP, DNS, and Traceroute checks for a specific URL."""
    url = db.session.get(MonitoredURL, url_id)
    if url is None or url.owner != current_user:
        flash('URL not found or permission denied.', 'danger')
        return redirect(url_for('dashboard'))

    now = datetime.now(timezone.utc)
    # Enforce 24-hour limit for the full scan - Compare aware times
    if url.last_full_scan and (now - url.last_full_scan) < timedelta(hours=23):
        time_since_last = now - url.last_full_scan
        hours_since = time_since_last.total_seconds() / 3600
        flash(f'Full scan already run recently ({hours_since:.1f} hours ago). Please wait.', 'warning')
        return redirect(url_for('view_url_details', url_id=url_id))

    # --- Perform Scans --- (These might take time)
    scan_results = {}
    parsed_url = urlparse(url.url)
    hostname = parsed_url.netloc

    try:
        app.logger.info(f"Starting full scan for {url.url} (ID: {url_id}) by user {current_user.username}")
        ip_address = get_ip_address(hostname)
        scan_results['ip_address'] = ip_address or 'Could not resolve IP'
        app.logger.debug(f"Full scan for {url.url}: IP resolved to {ip_address}")

        # RDAP Scan
        app.logger.debug(f"Full scan for {url.url}: Running RDAP scan...")
        rdap_data = get_rdap_info(ip_address) if ip_address else None
        # Pretty print the RDAP JSON data for display
        scan_results['rdap'] = json.dumps(rdap_data, indent=2) if rdap_data else 'RDAP lookup failed or no data.'

        # DNS Scan
        app.logger.debug(f"Full scan for {url.url}: Running DNS scan...")
        scan_results['dns'] = get_dns_records(hostname)

        # Traceroute Scan
        app.logger.debug(f"Full scan for {url.url}: Running Traceroute scan...")
        scan_results['traceroute'] = run_traceroute(hostname)

        # --- Update Timestamp and Save Results to DB ---
        url.last_full_scan = now # Already UTC
        url.last_scan_ip = ip_address
        url.last_scan_rdap = scan_results['rdap'] # Already JSON string or error message
        # Convert DNS dict to JSON string for storage
        url.last_scan_dns = json.dumps(scan_results['dns'])
        url.last_scan_traceroute = scan_results['traceroute']

        db.session.commit()
        app.logger.info(f"Full scan completed successfully for {url.url} (ID: {url_id}) and results saved.")
        flash('Full scan completed and results saved!', 'success')

        # --- Re-render Detail Page with Scan Results using Helper ---
        # Fetch the updated context using the helper function
        # Pass the already fetched url object to avoid another query
        context = _get_url_details_context(url_id, url)
        if context is None:
             flash('Error retrieving URL details after scan.', 'danger')
             return redirect(url_for('dashboard'))

        # Update the scan_results in the context with the *just* completed scan
        # This ensures the latest data is shown immediately without relying on the DB read in the helper
        context['scan_results'] = scan_results

        return render_template('url_details.html', **context)

    except Exception as e:
        db.session.rollback() # Rollback timestamp update if scan fails badly
        app.logger.error(f"Error during full scan execution for URL ID {url_id}: {e}", exc_info=True)
        flash('An unexpected error occurred during the full scan.', 'danger')
        return redirect(url_for('view_url_details', url_id=url_id))


@app.route('/url/<int:url_id>/export/pdf')
@login_required
def export_url_details_pdf(url_id):
    """Exports the details and history of a monitored URL to a PDF file."""
    url = db.session.get(MonitoredURL, url_id)
    if url is None or url.owner != current_user:
        flash('URL not found or permission denied.', 'danger')
        return redirect(url_for('dashboard'))

    # Fetch all necessary data for the PDF (similar to view_url_details, but maybe more logs)
    history_logs = db.session.scalars(
        sa.select(MonitoringLog)
        .where(MonitoringLog.monitored_url_id == url.id)
        .order_by(MonitoringLog.timestamp.desc())
        # Potentially fetch more logs for the PDF, e.g., limit(200) or all?
        # Be mindful of performance if fetching all logs for very long histories.
        .limit(200)
    ).all()

    # Fetch latest log for status
    latest_log = history_logs[0] if history_logs else None

    # Uptime calculation (copied from view_url_details - consider refactoring)
    now = datetime.now(timezone.utc)
    time_24h_ago = now - timedelta(hours=24)
    time_7d_ago = now - timedelta(days=7)

    # Use helper function for uptime
    uptime_24h, successful_checks_24h, total_checks_24h = _calculate_uptime_stats(url_id, time_24h_ago)
    uptime_7d, successful_checks_7d, total_checks_7d = _calculate_uptime_stats(url_id, time_7d_ago)

    # Use the module-level helper function
    last_scan_rdap_data = parse_json_string(url.last_scan_rdap, app.logger)
    last_scan_dns_data = parse_json_string(url.last_scan_dns, app.logger)

    # Render an HTML template specifically designed for PDF output
    html_string = render_template(
        'pdf_template.html',
        url=url,
        latest_log=latest_log,
        history_logs=history_logs,
        uptime_24h=uptime_24h,
        successful_checks_24h=successful_checks_24h,
        total_checks_24h=total_checks_24h,
        uptime_7d=uptime_7d,
        successful_checks_7d=successful_checks_7d,
        total_checks_7d=total_checks_7d,
        now=datetime.now(timezone.utc), # Pass current time for report date
        # Pass scan results (parsed or raw)
        last_scan_ip=url.last_scan_ip,
        last_scan_rdap=last_scan_rdap_data, # Parsed JSON or None
        last_scan_dns=last_scan_dns_data,   # Parsed JSON or None
        last_scan_traceroute=url.last_scan_traceroute,
        last_full_scan_time=url.last_full_scan # Pass the timestamp too
    )

    # Generate PDF using WeasyPrint
    # We can add basic CSS directly or link to a specific PDF CSS file
    pdf_bytes = HTML(string=html_string).write_pdf()

    # Create response
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    # Sanitize filename
    safe_filename = "".join([c for c in (url.name or url.url) if c.isalpha() or c.isdigit() or c in ('_','-')]).rstrip()
    response.headers['Content-Disposition'] = f'attachment; filename="{safe_filename}_report.pdf"'

    return response
