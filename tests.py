import unittest
from app import app, db
from app.models import User, MonitoredURL, MonitoringLog
import sqlalchemy as sa
from datetime import datetime, timezone
import os
import tempfile
import time

class WebsiteMonitorTests(unittest.TestCase):
    def setUp(self):
        # Create a temporary database for testing
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.client = app.test_client()
        
        with app.app_context():
            # Create all tables
            db.create_all()
            
            # Create a test user
            user = User(username='testuser', email='test@example.com')
            user.set_password('password')
            db.session.add(user)
            db.session.commit()
            
            # Create a test URL
            url = MonitoredURL(url='https://example.com', name='Test URL', user_id=user.id)
            db.session.add(url)
            db.session.commit()
            
            self.user_id = user.id
            self.url_id = url.id

    def tearDown(self):
        # Close and remove the temporary database
        with app.app_context():
            db.session.remove()
            db.drop_all()
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def login(self, username, password):
        return self.client.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)

    def test_login_logout(self):
        # Test login with correct credentials
        response = self.login('testuser', 'password')
        self.assertIn(b'Dashboard', response.data)
        
        # Test logout
        response = self.logout()
        self.assertIn(b'Sign In', response.data)
        
        # Test login with incorrect credentials
        response = self.login('testuser', 'wrongpassword')
        self.assertIn(b'Invalid username or password', response.data)

    def test_delete_url_requires_post(self):
        # Login first
        self.login('testuser', 'password')
        
        # Try to delete URL with GET request (should fail)
        response = self.client.get(f'/delete_url/{self.url_id}', follow_redirects=True)
        self.assertEqual(response.status_code, 405)  # Method Not Allowed
        
        # Verify URL still exists
        with app.app_context():
            url = db.session.get(MonitoredURL, self.url_id)
            self.assertIsNotNone(url)
        
        # Delete URL with POST request (should succeed)
        response = self.client.post(f'/delete_url/{self.url_id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'URL deleted successfully', response.data)
        
        # Verify URL is deleted
        with app.app_context():
            url = db.session.get(MonitoredURL, self.url_id)
            self.assertIsNone(url)

    def test_batch_url_check(self):
        # Login first
        self.login('testuser', 'password')
        
        # Add a few more URLs for testing batch processing
        urls = [
            'https://example.org',
            'https://example.net',
            'https://example.edu'
        ]
        
        url_ids = []
        for url in urls:
            response = self.client.post('/add_url', data=dict(
                url=url,
                name=f'Test {url}'
            ), follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # Get the ID of the newly added URL
            with app.app_context():
                new_url = db.session.scalar(sa.select(MonitoredURL).where(MonitoredURL.url == url))
                self.assertIsNotNone(new_url)
                url_ids.append(new_url.id)
        
        # Import the batch check function and run it
        from app.tasks import run_batch_url_checks
        with app.app_context():
            run_batch_url_checks(max_workers=2)
            
            # Give some time for the checks to complete
            time.sleep(2)
            
            # Verify logs were created for all URLs
            for url_id in [self.url_id] + url_ids:
                logs = db.session.scalars(
                    sa.select(MonitoringLog)
                    .where(MonitoringLog.monitored_url_id == url_id)
                ).all()
                self.assertGreater(len(logs), 0)

if __name__ == '__main__':
    unittest.main()
