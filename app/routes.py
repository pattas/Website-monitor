from flask import render_template, flash, redirect, url_for, request, jsonify
from flask_login import current_user, login_user, logout_user, login_required
import sqlalchemy as sa
from app import app, db
from app.forms import LoginForm, RegistrationForm, AddURLForm
from app.models import User, MonitoredURL, MonitoringLog
from urllib.parse import urlsplit, urlparse
from datetime import datetime, timedelta, timezone
from sqlalchemy import desc
from app.checks import run_advanced_checks_for_url, get_ip_address, get_rdap_info, get_dns_records, run_traceroute
import json # For pretty printing RDAP

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

    # Fetch the latest log for each URL to display status
    urls_with_status = []
    for url in user_urls:
        latest_log = db.session.scalars(
            sa.select(MonitoringLog)
            .where(MonitoringLog.monitored_url_id == url.id)
            .order_by(MonitoringLog.timestamp.desc())
            .limit(1)
        ).first()
        urls_with_status.append({'url': url, 'latest_log': latest_log})

    return render_template('dashboard.html', title='Dashboard', form=form, urls_with_status=urls_with_status)

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
            db.session.commit()
            flash('URL added successfully!')
    else:
        # Handle form errors (e.g., invalid URL)
        for field, errors in form.errors.items():
            for error in errors:
                 flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/delete_url/<int:url_id>', methods=['GET', 'POST']) # GET for simplicity, POST recommended for deletion
@login_required
def delete_url(url_id):
    url_to_delete = db.session.get(MonitoredURL, url_id)
    if url_to_delete is None:
        flash('URL not found.', 'warning')
        return redirect(url_for('dashboard'))
    if url_to_delete.owner != current_user:
        flash('You do not have permission to delete this URL.', 'danger')
        return redirect(url_for('dashboard'))

    # Cascade delete will handle the logs automatically due to model definition
    # # Delete associated logs first (No longer needed)
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
    # Fetch URL and ensure ownership
    url = db.session.get(MonitoredURL, url_id)
    if url is None or url.owner != current_user:
        flash('URL not found or you do not have permission to view it.', 'warning')
        return redirect(url_for('dashboard'))

    # Fetch latest log for current status
    latest_log = db.session.scalars(
        sa.select(MonitoringLog)
        .where(MonitoringLog.monitored_url_id == url.id)
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
    # Define time thresholds
    now = datetime.now(timezone.utc)
    time_24h_ago = now - timedelta(hours=24)
    time_7d_ago = now - timedelta(days=7)

    # Helper function to calculate uptime
    def calculate_uptime(start_time):
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

    # Calculate uptime for 24h and 7d
    uptime_24h, successful_checks_24h, total_checks_24h = calculate_uptime(time_24h_ago)
    uptime_7d, successful_checks_7d, total_checks_7d = calculate_uptime(time_7d_ago)

    # --- Fetch Recent History --- (e.g., last 50 logs)
    history_logs = db.session.scalars(
        sa.select(MonitoringLog)
        .where(MonitoringLog.monitored_url_id == url.id)
        .order_by(MonitoringLog.timestamp.desc())
        .limit(50) # Limit the number of history logs displayed
    ).all()

    return render_template(
        'url_details.html',
        title=f"Details for {url.name or url.url}",
        url=url,
        latest_log=latest_log,
        current_status=current_status,
        uptime_24h=uptime_24h,
        successful_checks_24h=successful_checks_24h,
        total_checks_24h=total_checks_24h,
        uptime_7d=uptime_7d,
        successful_checks_7d=successful_checks_7d,
        total_checks_7d=total_checks_7d,
        history_logs=history_logs
    )

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
    # Check if last check was recent (e.g., within 23 hours)
    if url.last_advanced_check and (now.replace(tzinfo=None) - url.last_advanced_check) < timedelta(hours=23):
        time_since_last = now.replace(tzinfo=None) - url.last_advanced_check
        hours_since = time_since_last.total_seconds() / 3600
        flash(f'Advanced check already run recently ({hours_since:.1f} hours ago). Please wait.', 'warning')
        return redirect(url_for('view_url_details', url_id=url_id))

    try:
        print(f"Manual trigger for advanced checks on {url.url}")
        updated = run_advanced_checks_for_url(url)
        if updated:
            db.session.commit()
            flash('Advanced check completed and data updated.', 'success')
        else:
             # If updated is False, it means either the check failed or the data didn't change
             # We still update last_advanced_check time if the check itself ran without fundamental errors
             if url.last_advanced_check is None or (now.replace(tzinfo=None) - url.last_advanced_check) > timedelta(minutes=5):
                 url.last_advanced_check = now
                 db.session.commit()
             flash('Advanced check completed. No changes detected or check failed (see logs).', 'info')

    except Exception as e:
        db.session.rollback()
        print(f"Error during manual advanced check trigger: {e}")
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
    # Enforce 24-hour limit for the full scan
    if url.last_full_scan and (now.replace(tzinfo=None) - url.last_full_scan) < timedelta(hours=23):
        time_since_last = now.replace(tzinfo=None) - url.last_full_scan
        hours_since = time_since_last.total_seconds() / 3600
        flash(f'Full scan already run recently ({hours_since:.1f} hours ago). Please wait.', 'warning')
        return redirect(url_for('view_url_details', url_id=url_id))

    # --- Perform Scans --- (These might take time)
    scan_results = {}
    parsed_url = urlparse(url.url)
    hostname = parsed_url.netloc

    try:
        ip_address = get_ip_address(hostname)
        scan_results['ip_address'] = ip_address or 'Could not resolve IP'
        print(f"Scanning {hostname} ({ip_address})...")

        # RDAP Scan
        print("  Running RDAP scan...")
        rdap_data = get_rdap_info(ip_address) if ip_address else None
        # Pretty print the RDAP JSON data for display
        scan_results['rdap'] = json.dumps(rdap_data, indent=2) if rdap_data else 'RDAP lookup failed or no data.'

        # DNS Scan
        print("  Running DNS scan...")
        scan_results['dns'] = get_dns_records(hostname)

        # Traceroute Scan
        print("  Running Traceroute scan...")
        scan_results['traceroute'] = run_traceroute(hostname)

        # --- Update Timestamp and Commit ---
        url.last_full_scan = now
        db.session.commit()
        flash('Full scan completed!', 'success')

        # --- Re-render Detail Page with Scan Results --- #
        # We need to fetch all other data again, similar to view_url_details
        # This avoids storing potentially large results in the session or database

        latest_log = db.session.scalars(sa.select(MonitoringLog).where(MonitoringLog.monitored_url_id == url.id).order_by(MonitoringLog.timestamp.desc()).limit(1)).first()
        current_status = "UNKNOWN"
        if latest_log:
            if latest_log.status_code and latest_log.status_code >= 200 and latest_log.status_code < 300: current_status = "OK"
            elif latest_log.status_code: current_status = "WARN"
            else: current_status = "ERROR"

        time_24h_ago = now - timedelta(hours=24)
        time_7d_ago = now - timedelta(days=7)

        def calculate_uptime(start_time):
            # Simplified for brevity - ideally refactor this too
            logs = db.session.scalars(sa.select(MonitoringLog).where(MonitoringLog.monitored_url_id == url_id, MonitoringLog.timestamp >= start_time)).all()
            total = len(logs)
            success = sum(1 for log in logs if log.status_code and 200 <= log.status_code < 300)
            return (success / total * 100) if total > 0 else 100.0, success, total

        uptime_24h, s24, t24 = calculate_uptime(time_24h_ago)
        uptime_7d, s7, t7 = calculate_uptime(time_7d_ago)
        history_logs = db.session.scalars(sa.select(MonitoringLog).where(MonitoringLog.monitored_url_id == url.id).order_by(MonitoringLog.timestamp.desc()).limit(50)).all()

        return render_template(
            'url_details.html',
            title=f"Details for {url.name or url.url}",
            url=url,
            latest_log=latest_log,
            current_status=current_status,
            uptime_24h=uptime_24h,
            successful_checks_24h=s24,
            total_checks_24h=t24,
            uptime_7d=uptime_7d,
            successful_checks_7d=s7,
            total_checks_7d=t7,
            history_logs=history_logs,
            scan_results=scan_results # Pass the new scan results
        )

    except Exception as e:
        db.session.rollback() # Rollback timestamp update if scan fails badly
        print(f"Error during full scan execution: {e}")
        flash('An unexpected error occurred during the full scan.', 'danger')
        return redirect(url_for('view_url_details', url_id=url_id))
