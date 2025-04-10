# Flask Website Uptime & Details Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask Version](https://img.shields.io/badge/flask-2.x%20%7C%203.x-brightgreen.svg) <!-- Adjust Flask version if known -->

A web application built with Flask and Python to monitor website uptime, response time, SSL/domain expiration, and perform diagnostic checks like RDAP, DNS lookups, and traceroute.

## ✨ Features

*   **🔒 User Authentication:** Secure registration and login.
*   **➕ URL Management:** Add, view details, and remove URLs for monitoring.
*   **📊 Dashboard:** Overview of monitored URLs with current status (OK, Warn, Error), name, and last check time.
*   **⚙️ Background Monitoring:** Uses APScheduler for periodic checks:
    *   **Frequent:** Website availability (Status Code) & Response Time.
    *   **Daily (Configurable):** SSL Certificate & Domain Name Expiry (via WHOIS).
*   **📈 Detailed URL View:**
    *   Current status & last check timestamp.
    *   SSL/Domain expiry dates & days remaining.
    *   Uptime percentages (24 hours, 7 days).
    *   Interactive response time chart (Chart.js, last 24 hours).
    *   Recent monitoring history table.
    *   Stored results from the last full diagnostic scan.
*   **🔍 Manual Scans (Rate-Limited):**
    *   Refresh SSL/Domain info (~24h cooldown).
    *   Run full diagnostic scan (RDAP, DNS, Traceroute) (~24h cooldown).
*   **📄 PDF Export:** Generate a PDF report for a specific URL, including details, history, uptime stats, and last scan results.
*   **🎨 Modern UI:** Clean interface using Bootstrap 5 (Bootswatch Pulse) and Font Awesome.

## 📖 Application Overview

This application provides a centralized dashboard to monitor the health and status of multiple websites or web services. Key functionalities include:

*   **Uptime Monitoring:** Regularly checks if your websites are online and accessible.
*   **Performance Tracking:** Measures how quickly your websites respond.
*   **SSL & Domain Health:** Checks the expiration dates of SSL certificates and domain names to prevent unexpected downtime or security warnings.
*   **Diagnostics:** Performs deeper checks like RDAP (domain registration details), DNS record lookups, and traceroute (network path analysis) to help diagnose connectivity issues.
*   **History & Reporting:** Keeps a log of checks, displays trends over time with charts, and allows exporting detailed reports to PDF.
*   **User Management:** Supports multiple user accounts with secure login.

It's designed for web administrators, developers, or anyone who needs to keep an eye on the availability and performance of web assets.

## 📸 Screenshots

*(Please add your own screenshots here after setting up the project and uploading them to your repository. Example placeholders below)*

*   `![Dashboard Screenshot](dashboard.png)`
*   `![URL Details Screenshot](details.png)`
*   `![Login Screenshot](login.png)`
*   `![PDF Export Example](pdf_example.png)`

## 🛠️ Technologies Used

*   **Backend:** Python 3, Flask
*   **Database:** SQLAlchemy ORM, Flask-Migrate (SQLite default)
*   **Scheduling:** APScheduler
*   **Authentication:** Flask-Login
*   **Forms:** Flask-WTF
*   **HTTP:** requests
*   **SSL/Domain:** `cryptography`, `ssl`, `socket`, `python-whois`
*   **Diagnostics:** `ipwhois` (RDAP), `dnspython` (DNS), `subprocess` (Traceroute)
*   **PDF:** WeasyPrint
*   **Frontend:** HTML, CSS, JavaScript, Jinja2, Bootstrap 5, Chart.js, Font Awesome
*   **Configuration:** python-dotenv (`.env`)

## 📋 Prerequisites

*   **Python:** Version 3.8 or higher recommended.
*   **pip:** Python package installer (usually comes with Python).
*   **git:** For cloning and version control.
*   **Traceroute:** A command-line traceroute utility (`traceroute`, `tcptraceroute`, or `tracert` on Windows) must be installed and accessible in the system's PATH.
    *   *Linux (Debian/Ubuntu):* `sudo apt update && sudo apt install -y traceroute tcptraceroute`
    *   *Linux (Fedora):* `sudo dnf install -y traceroute tcptraceroute`
    *   *macOS (Homebrew):* `brew install traceroute tcptraceroute`
*   **WeasyPrint Dependencies:** Required for PDF generation. Installation varies by OS. See [WeasyPrint Documentation](https://doc.courtbouillon.org/weasyprint/stable/install.html) for details. Common commands:
    *   *Linux (Debian/Ubuntu):* `sudo apt install -y build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info`
    *   *Linux (Fedora):* `sudo dnf install -y python3-devel python3-pip python3-setuptools python3-wheel python3-cffi cairo pango gdk-pixbuf2 libffi-devel`
    *   *macOS (Homebrew):* `brew install pango gdk-pixbuf libffi`

## 🚀 Setup & Installation

1.  **Clone the Repository:**
    ```bash
    git clone <your-repository-url> # Replace with your repo URL after uploading
    cd <repository-directory-name>
    ```

2.  **Create & Activate Virtual Environment:**
    ```bash
    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

    # Windows (cmd)
    # python -m venv venv
    # venv\Scripts\activate.bat

    # Windows (PowerShell)
    # python -m venv venv
    # .\venv\Scripts\Activate.ps1
    # (You might need: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process)
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment:**
    *   Create a `.env` file in the project root:
        ```dotenv
        # --- Flask Secret Key (Required!) ---
        # Generate a strong, random secret key for session security.
        # Example (replace with your own!):
        SECRET_KEY='generate_a_super_secret_random_string_here'

        # --- Database URL (Optional) ---
        # Defaults to SQLite (app.db in the instance folder).
        # Uncomment and modify to use PostgreSQL, MySQL, etc.
        # DATABASE_URL='postgresql://user:password@host:port/dbname'

        # --- Check Intervals (Optional) ---
        # Defaults are in config.py. Uncomment to override.
        # STANDARD_CHECK_INTERVAL_MINUTES=5
        # ADVANCED_CHECK_INTERVAL_HOURS=24
        ```
    *   **IMPORTANT:** The `.env` file contains sensitive information like your `SECRET_KEY`. Ensure it is **NEVER** committed to Git. (A `.gitignore` file is included to help prevent this).

5.  **Initialize Database:**
    *   Set the `FLASK_APP` environment variable (needed for `flask` commands):
        ```bash
        # Linux/macOS
        export FLASK_APP=app:app

        # Windows (cmd)
        # set FLASK_APP=app:app

        # Windows (PowerShell)
        # $env:FLASK_APP = "app:app"
        ```
    *   Apply database migrations (this creates `app.db` and tables):
        ```bash
        flask db upgrade
        ```
        *(If you ever need to reset/recreate migrations, delete the `migrations` folder and `app.db` file, then run `flask db init`, `flask db migrate -m "Initial migration"`, `flask db upgrade`)*

## ▶️ Running the Application

1.  Ensure your virtual environment is activated (Setup Step 2).
2.  Ensure `FLASK_APP` is set (Setup Step 5).
3.  Run the Flask development server:
    ```bash
    flask run
    ```
    *   The web application and the background scheduler will start automatically.
    *   Open your web browser and navigate to the address shown in the terminal (usually `http://127.0.0.1:5000` or `http://localhost:5000`).

## 📖 User Guide (How to Use the Monitor)

1.  **Access the App:** Open the application URL (e.g., `http://127.0.0.1:5000`) in your browser.
2.  **Register:** If you're a new user, click the "Register" link and create an account with a username and password.
3.  **Login:** Use your registered credentials to log in.
4.  **Dashboard View:** After logging in, you'll see the main Dashboard. Initially, it will be empty.
5.  **Add a Website:**
    *   Find the "Add New URL" section on the Dashboard.
    *   Enter the full URL of the website you want to monitor (e.g., `https://www.example.com`). Make sure to include `http://` or `https://`.
    *   Optionally, give it a friendly name (e.g., "Example Corp Website") for easier identification.
    *   Click "Add URL".
6.  **Monitoring Begins:** The application will start monitoring the added URL automatically in the background based on the configured intervals. The Dashboard will update periodically showing the current status (OK, Warning, Error), the URL name, and the time of the last check.
7.  **View Details:**
    *   On the Dashboard, find the URL you're interested in.
    *   Click the **eye icon** (<i class="fas fa-eye"></i>) in the "Actions" column next to the URL.
    *   This takes you to the **URL Detail Page**.
8.  **Explore Details Page:**
    *   **Key Stats:** See the current status, SSL/Domain expiry dates (and days remaining), and recent uptime percentages.
    *   **Full Scan Results:** If a full scan has been run recently, you'll see sections for RDAP (domain registration info), DNS records, and Traceroute results. The RDAP data should now be nicely formatted.
    *   **Response Time Chart:** An interactive chart shows the website's response time over the last 24 hours. Hover over points for exact times.
    *   **Recent History:** A table lists the most recent checks, showing the timestamp, status code, response time, and any errors.
9.  **Manual Actions (on Detail Page):**
    *   **Refresh SSL/Domain:** Click this button to manually trigger an immediate check for SSL certificate and domain expiry information. *Note: This is usually rate-limited to once every 24 hours per URL.*
    *   **Run Full Scan:** Click this to perform the RDAP, DNS, and Traceroute checks immediately. *Note: Also typically rate-limited.*
    *   **Export PDF:** Click this to generate and download a PDF report containing all the details shown on the page.
10. **Removing a URL:**
    *   Go back to the **Dashboard**.
    *   Find the URL you want to remove.
    *   Click the **trash can icon** (<i class="fas fa-trash-alt"></i>) in the "Actions" column.
    *   Confirm the deletion.

## ⬆️ Uploading to GitHub

Follow these steps to upload your project to a new GitHub repository:

1.  **Ensure Git is Initialized:** If you haven't already, initialize Git in your project's root directory:
    ```bash
    git init
    ```

2.  **Create `.gitignore`:** Create a file named `.gitignore` in the project root. This file tells Git which files or directories to ignore. A good starting point:
    ```gitignore
    # Virtual environment
    venv/
    env/
    */venv/
    */env/
    .venv

    # Python cache
    __pycache__/
    *.py[cod]
    *$py.class

    # Database file (Default: instance/app.db)
    app.db
    *.sqlite
    *.sqlite3
    instance/

    # Environment variables (VERY IMPORTANT!)
    .env
    *.env

    # IDE / Editor specific
    .idea/
    .vscode/
    *.suo
    *.ntvs*
    *.njsproj
    *.sln
    *.sw?

    # OS specific
    .DS_Store
    Thumbs.db

    # Build artifacts
    dist/
    build/
    *.egg-info/

    # Downloaded dependencies (WeasyPrint etc., if vendored)
    # Add specific paths if needed
    ```
    **Verify:** Check that `app.db` (or the `instance` folder) and `.env` are listed in your `.gitignore`.

3.  **Create a Repository on GitHub:** Go to [GitHub](https://github.com/) and create a new, empty repository. Do *not* initialize it with a README, .gitignore, or license file on GitHub initially, as you'll be pushing your local versions.

4.  **Add Files to Git:** Stage all your project files (Git will automatically skip ignored files):
    ```bash
    git add .
    ```

5.  **Commit Files:** Create your first commit:
    ```bash
    git commit -m "Initial commit: Add project files"
    ```

6.  **Link Local Repo to GitHub:** Connect your local repository to the remote one you created on GitHub. Replace `<YourGitHubUsername>` and `<YourRepositoryName>`:
    ```bash
    git remote add origin https://github.com/<YourGitHubUsername>/<YourRepositoryName>.git
    ```

7.  **Push to GitHub:** Push your local `main` (or `master`) branch to the remote `origin`:
    ```bash
    git push -u origin main # Or 'master' if that's your default branch name
    ```

Your code should now be on GitHub! Remember to update the screenshot links in this README after uploading them to the repository.

## 🙌 Contributing

Contributions, issues, and feature requests are welcome!

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file (if present) for details.
