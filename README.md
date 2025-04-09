# Flask Website Uptime & Details Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) <!-- Optional License Badge -->

A web application built with Flask and Python to monitor website uptime, response time, SSL/domain expiration, and perform diagnostic checks.

## Features

*   **User Authentication:** Secure user registration and login system.
*   **URL Monitoring:** Add, view, and delete URLs to monitor.
*   **Dashboard Overview:** Displays a list of monitored URLs with current status indicators (OK, Warning, Error).
*   **Background Checks:** A separate script (`monitor.py`) periodically checks:
    *   Website accessibility (Status Code)
    *   Response time
    *   SSL Certificate Expiry (approx. once daily)
    *   Domain Name Expiry (WHOIS lookup, approx. once daily, can be unreliable)
*   **Detailed View:** Dedicated page for each URL showing:
    *   Current status and last check time.
    *   SSL and Domain expiry dates (with days remaining).
    *   Uptime statistics (calculated for the last 24 hours and 7 days).
    *   Response time history chart (last 24 hours).
    *   Table of recent check history.
*   **Manual Scans (with Rate Limiting):**
    *   Button to manually refresh SSL/Domain expiry data (max once per ~24h).
    *   Button to run a full diagnostic scan (RDAP, DNS Records, Traceroute) (max once per ~24h).
*   **Data Visualization:** Interactive charts using Chart.js.
*   **Modern UI:** Clean interface using Bootstrap 5 (Bootswatch Pulse theme) and Font Awesome icons.

## Screenshot


![image](https://github.com/user-attachments/assets/90edc8bc-a81d-403a-954c-66b63d053bd1)
![image](https://github.com/user-attachments/assets/92b40180-85dc-4fb4-bb5a-c73aeb1967d7)
![image](https://github.com/user-attachments/assets/b4b456d8-ad44-4e58-845a-8bf8cc1d6f30)
![image](https://github.com/user-attachments/assets/7a8b4aee-b565-45cf-b159-ea8146163680)



## Technologies Used

*   **Backend:** Python 3, Flask
*   **Database:** SQLite (default), SQLAlchemy ORM, Flask-Migrate
*   **Authentication:** Flask-Login
*   **Forms:** Flask-WTF
*   **HTTP Requests:** requests
*   **SSL Checks:** cryptography, ssl, socket
*   **WHOIS Lookup:** python-whois
*   **RDAP Lookup:** ipwhois
*   **DNS Lookup:** dnspython
*   **Diagnostics:** subprocess (for traceroute)
*   **Frontend:** HTML, CSS, JavaScript
*   **UI Framework:** Bootstrap 5 (Bootswatch Pulse theme)
*   **Charting:** Chart.js (with date-fns adapter)
*   **Icons:** Font Awesome
*   **Templating:** Jinja2
*   **Configuration:** python-dotenv (.env file)

## Prerequisites

*   Python 3 (version 3.8 or higher recommended)
*   `pip` (Python package installer)
*   `git` (for cloning the repository)
*   `traceroute` command-line tool:
    *   **Debian/Ubuntu:** `sudo apt update && sudo apt install traceroute`
    *   **Fedora/CentOS:** `sudo dnf install traceroute`
    *   **macOS:** Usually pre-installed or via Homebrew (`brew install traceroute`)
    *   **Windows:** Uses built-in `tracert`. Ensure it's in your system's PATH.

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory-name>
    ```

2.  **Create and activate a virtual environment:**
    *   **Linux/macOS:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    *   **Windows (cmd):**
        ```bash
        python -m venv venv
        venv\Scripts\activate.bat
        ```
    *   **Windows (PowerShell):**
        ```bash
        python -m venv venv
        .\venv\Scripts\Activate.ps1
        ```
        *(Note: You might need to adjust PowerShell execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`)*

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize and migrate the database:**
    *   Set the Flask application environment variable:
        *   **Linux/macOS:** `export FLASK_APP=app:app`
        *   **Windows (cmd):** `set FLASK_APP=app:app`
        *   **Windows (PowerShell):** `$env:FLASK_APP = "app:app"`
    *   Initialize the migration repository (only if the `migrations` folder doesn't exist):
        ```bash
        flask db init
        ```
    *   Generate the initial migration script:
        ```bash
        flask db migrate -m "Initial database migration"
        ```
    *   Apply the migration to create the database tables:
        ```bash
        flask db upgrade
        ```
        *(This will create the `app.db` SQLite file in the project root)*

5.  **(Optional) Create a `.env` file:**
    Create a file named `.env` in the project root directory.
    Add a `SECRET_KEY` for Flask session security:
    ```dotenv
    SECRET_KEY='your-very-secret-and-random-key-here'
    # You could also override DATABASE_URL here if you switch from SQLite
    # DATABASE_URL='postgresql://user:password@host:port/dbname'
    ```
    If you don't create this, a default (less secure) secret key will be used.

## Running the Application

You need to run two separate processes:

1.  **The Background Monitoring Script:**
    This script performs the periodic checks.
    Open a terminal, activate the virtual environment (`source venv/bin/activate`), and run:
    ```bash
    python monitor.py
    ```
    *   This script needs to run continuously in the background.
    *   For long-term running on a server, consider using a process manager like `systemd`, `supervisor`, or running it inside a terminal multiplexer like `screen` or `tmux` (`screen -S monitor python monitor.py`, then detach with `Ctrl+A`, `D`).

2.  **The Flask Web Server:**
    This serves the web interface.
    Open *another* terminal, activate the virtual environment (`source venv/bin/activate`), ensure `FLASK_APP` is set, and run:
    ```bash
    flask run
    ```
    *   The application will typically be available at `http://127.0.0.1:5000` (or the port specified).

## Usage

1.  Open your web browser and navigate to `http://127.0.0.1:5000` (or the address provided by `flask run`).
2.  **Register** a new user account.
3.  **Login** with your credentials.
4.  You will be redirected to the **Dashboard**.
5.  Use the **"Add New URL"** form to add websites you want to monitor (e.g., `https://google.com`). You can provide an optional friendly name.
6.  The dashboard list shows monitored URLs with a status icon (based on the latest check from `monitor.py`).
7.  Click the **eye icon** (<i class="fas fa-eye"></i>) next to a URL to view the **Detail Page**.
8.  The detail page shows current status, uptime stats, SSL/Domain expiry info, a response time chart, and recent check history.
9.  On the detail page, you can use the manual scan buttons:
    *   **"Refresh SSL/Domain"**: Triggers an immediate check for SSL and Domain expiry (limit: once per ~24h).
    *   **"Run Full Scan"**: Triggers RDAP, DNS, and Traceroute checks (limit: once per ~24h). Results are displayed on the page after the scan completes.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License - see the LICENSE file (if added) for details. 
