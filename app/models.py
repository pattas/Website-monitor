from datetime import datetime, timezone
from typing import Optional, List
import sqlalchemy as sa
import sqlalchemy.orm as so
from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), index=True, unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    urls: so.WriteOnlyMapped['MonitoredURL'] = so.relationship(back_populates='owner')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))

class MonitoredURL(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    url: so.Mapped[str] = so.mapped_column(sa.String(200), index=True)
    name: so.Mapped[Optional[str]] = so.mapped_column(sa.String(100)) # Optional name for the URL
    added_at: so.Mapped[datetime] = so.mapped_column(index=True, default=lambda: datetime.now(timezone.utc))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id), index=True)
    owner: so.Mapped[User] = so.relationship(back_populates='urls')
    logs: so.Mapped[List['MonitoringLog']] = so.relationship(
        back_populates='monitored_url',
        cascade="all, delete-orphan",
        lazy='dynamic'
    )
    # Fields for advanced checks
    ssl_expiry_date: so.Mapped[Optional[datetime]] = so.mapped_column(nullable=True)
    domain_expiry_date: so.Mapped[Optional[datetime]] = so.mapped_column(nullable=True)
    last_advanced_check: so.Mapped[Optional[datetime]] = so.mapped_column(nullable=True) # Timestamp of the last attempt
    last_successful_advanced_check: so.Mapped[Optional[datetime]] = so.mapped_column(nullable=True) # Timestamp of last success
    last_full_scan: so.Mapped[Optional[datetime]] = so.mapped_column(nullable=True)

    # Fields to store last full scan results
    last_scan_ip: so.Mapped[Optional[str]] = so.mapped_column(sa.String(45), nullable=True) # IPv6 compatible length
    last_scan_rdap: so.Mapped[Optional[str]] = so.mapped_column(sa.Text, nullable=True) # Store JSON as text
    last_scan_dns: so.Mapped[Optional[str]] = so.mapped_column(sa.Text, nullable=True) # Store JSON as text
    last_scan_traceroute: so.Mapped[Optional[str]] = so.mapped_column(sa.Text, nullable=True)

    def __repr__(self):
        return f'<MonitoredURL {self.url}>'

class MonitoringLog(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    timestamp: so.Mapped[datetime] = so.mapped_column(index=True, default=lambda: datetime.now(timezone.utc))
    status_code: so.Mapped[Optional[int]] = so.mapped_column()
    response_time_ms: so.Mapped[Optional[float]] = so.mapped_column()
    error_message: so.Mapped[Optional[str]] = so.mapped_column(sa.String(200))
    monitored_url_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(MonitoredURL.id), index=True)
    monitored_url: so.Mapped[MonitoredURL] = so.relationship(back_populates='logs')

    def __repr__(self):
        return f'<MonitoringLog {self.monitored_url.url} at {self.timestamp}>'
