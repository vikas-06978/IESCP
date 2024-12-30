# Copyright (c) 2024 Vikas-06978
# Licensed under the MIT License
# Unauthorized copying of this file, via any medium, is strictly prohibited
# Written by Vikas


from app import app 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint
from werkzeug.security import generate_password_hash
from datetime import datetime
from flask_login import UserMixin


db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(64), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    admins = db.relationship('Admin', backref='user', uselist=False)
    sponsors = db.relationship('Sponsor', backref='user', uselist=False)
    influencers = db.relationship('Influencer', backref='user', uselist=False)
    
    @property
    def is_influencer(self):
        return self.role == 'influencer'
    
    @property
    def is_sponsor(self):
        return self.role == 'sponsor'
    
   
    
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin_name = db.Column(db.String(50), unique=True, nullable=False)
    age = db.Column(db.Integer, CheckConstraint('age >= 0 AND age <= 120'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

class Sponsor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sponsor_name = db.Column(db.String(50), unique=True, nullable=False)
    industry = db.Column(db.String(50), nullable=False)
    budget = db.Column(db.Float, nullable=False)
    establishment = db.Column(db.Date, nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    influencers = db.relationship('Influencer', backref='sponsor', uselist=False, foreign_keys=[influencer_id])
    
    # Relationships
    set_entries = db.relationship('SetCampaignAdRequest', back_populates='sponsor')
    campaigns = db.relationship('Campaign', backref='sponsor', cascade="all, delete-orphan", lazy=True)

class Influencer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    influencer_name = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    age = db.Column(db.Integer, CheckConstraint('age >= 0 AND age <= 120'), nullable=False)
    niche = db.Column(db.String(50), nullable=False)
    reach = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=True)
    
    # Relationships
    sponsors = db.relationship('Sponsor', backref='influencer', uselist=False, foreign_keys=[sponsor_id])
    add_requests = db.relationship('AddRequest', backref='influencer', cascade="all, delete-orphan", lazy=True)

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)
    sponsor_name = db.Column(db.String(50), nullable=False)
    campaign_name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    visibility = db.Column(db.String(10), nullable=False, default='private')
    goals = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    set_entries = db.relationship('SetCampaignAdRequest', back_populates='campaign')

    add_requests = db.relationship('AddRequest', backref='campaign', cascade="all, delete-orphan", lazy=True)

class AddRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    influencer_id = db.Column(db.Integer, db.ForeignKey('influencer.id'), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'))
    campaign_name = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(255), nullable=True)
    requirements = db.Column(db.String(255), nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')
    set_entries = db.relationship('SetCampaignAdRequest', back_populates='ad_request')
    is_active = db.Column(db.Boolean, default=True)
    
    sponsor = db.relationship('Sponsor', backref='ad_requests')
    
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Refers to the sponsor
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Refers to the influencer
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=True)
    ad_request_id = db.Column(db.Integer, db.ForeignKey('add_request.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Pending')

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('sent_notifications', lazy=True))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('received_notifications', lazy=True))
    campaign = db.relationship('Campaign', backref=db.backref('notifications', lazy=True), uselist=False)
    ad_request = db.relationship('AddRequest', backref=db.backref('notifications', lazy=True), uselist=False)

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:30]}"


class SponsorNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=True)
    ad_request_id = db.Column(db.Integer, db.ForeignKey('add_request.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Pending')

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('sponsor_notifications_sent', lazy=True))
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref=db.backref('sponsor_notifications_received', lazy=True))
    campaign = db.relationship('Campaign', backref=db.backref('sponsor_notifications', lazy=True), uselist=False)
    ad_request = db.relationship('AddRequest', backref=db.backref('sponsor_notifications', lazy=True), uselist=False)

    def __str__(self):
        return f"Notification for {self.user.username}: {self.message[:30]}"

    
class SetCampaignAdRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=False)
    ad_request_id = db.Column(db.Integer, db.ForeignKey('add_request.id'), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('sponsor.id'), nullable=False)  # Add this line to link the sponsor

    campaign = db.relationship('Campaign', back_populates='set_entries')
    ad_request = db.relationship('AddRequest', back_populates='set_entries')
    sponsor = db.relationship('Sponsor', back_populates='set_entries') 


def mark_notification_as_read(notification_id, notification_type):
    """
    Marks all notifications as read for the Notification model that match the given ID.

    :param notification_id: The ID of the notification to mark as read.
    :param notification_type: The type of notification ('campaign' or 'ad_request').
    """
    notifications = []
    if notification_type == 'campaign':
        notifications = Notification.query.filter_by(campaign_id=notification_id).all()
    elif notification_type == 'ad_request':
        notifications = Notification.query.filter_by(ad_request_id=notification_id).all()

    if notifications:
        for notification in notifications:
            notification.is_read = True
        db.session.commit()
        print(f"All notifications for {notification_type} {notification_id} marked as read.")
    else:
        print(f"No notifications found for ID: {notification_id} and type: {notification_type}")

def mark_sponsor_notification_as_read(notification_id, notification_type):
    """
    Marks all sponsor notifications as read for the SponsorNotification model that match the given ID.

    :param notification_id: The ID of the notification to mark as read.
    :param notification_type: The type of notification ('campaign' or 'ad_request').
    """
    notifications = []
    if notification_type == 'campaign':
        notifications = SponsorNotification.query.filter_by(campaign_id=notification_id).all()
    elif notification_type == 'ad_request':
        notifications = SponsorNotification.query.filter_by(ad_request_id=notification_id).all()

    if notifications:
        for notification in notifications:
            notification.is_read = True
        db.session.commit()
        print(f"All sponsor notifications for {notification_type} {notification_id} marked as read.")
    else:
        print(f"No sponsor notifications found for ID: {notification_id} and type: {notification_type}")


with app.app_context():
    db.create_all()

    # Create an admin user if it doesn't exist
    admin_user = User.query.filter_by(role='admin').first()
    if not admin_user:
        password_hash = generate_password_hash('admin')
        admin_user = User(username='admin', passhash=password_hash, name='Admin', role='admin', email='admin123@gmail.com')
        db.session.add(admin_user)
        db.session.commit()
        admin = Admin(user_id=admin_user.id, admin_name='Admin Name', age=28)
        db.session.add(admin)
        db.session.commit()
    
    # Create a sponsor user if it doesn't exist
    sponsor_user = User.query.filter_by(role='sponsor').first()
    if not sponsor_user:
        password_hash = generate_password_hash('sponsor')
        sponsor_user = User(username='sponsor', passhash=password_hash, name='Sponsor', role='sponsor', email='sponsor123@gmail.com')
        db.session.add(sponsor_user)
        db.session.commit()
        sponsor = Sponsor(user_id=sponsor_user.id, sponsor_name='Sponsor Name', industry='Industry', budget=10000, establishment=datetime.today())
        db.session.add(sponsor)
        db.session.commit()
    
    # Create an influencer user if it doesn't exist
    influencer_user = User.query.filter_by(role='influencer').first()
    if not influencer_user:
        password_hash = generate_password_hash('influencer')
        influencer_user = User(username='influencer', passhash=password_hash, name='Influencer', role='influencer', email='influencer123@gmail.com')
        db.session.add(influencer_user)
        db.session.commit()
        influencer = Influencer(user_id=influencer_user.id, influencer_name='Influencer Name', category='Category', niche='Niche', reach=1000, age=25)
        db.session.add(influencer)
        db.session.commit()


    influencer = Influencer.query.first()
    sponsor = Sponsor.query.first()

    if influencer and sponsor:
        db.session.commit()
