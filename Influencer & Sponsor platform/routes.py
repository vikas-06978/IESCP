# Copyright (c) 2024 Vikas-06978
# Licensed under the MIT License
# Unauthorized copying of this file, via any medium, is strictly prohibited
# Written by Vikas


from flask import render_template, request, redirect, url_for, flash, session, jsonify
from app import app, login_manager
from models import *
from flask_login import current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods= ["POST", "GET"])
def login():
    if request.method=="POST":
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        role = request.form.get('role')

        
        if not identifier or not password:
            flash('Please fill out all the fields', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if not user:
            flash('User or Email does not exits','danger')
            return redirect(url_for('login'))
        if not check_password_hash(user.passhash, password):
            flash('Incorrect password', 'danger')
            return redirect(url_for('login'))
        if user.role != role:
            flash("please select correct role",'warning')
            return redirect(url_for('login'))
        
        session['user_id'] = user.id 
        flash("Login Successfully", 'success')
        return redirect(url_for(role))
    return render_template('login.html')
    



@app.route('/register')
def register():
    return render_template('register.html')

# decorator for auth_required

def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'info')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner
    


def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'info')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You are not authorized to access this page', 'warning')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner

def sponsor_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        # Check if 'user_id' is in session
        if 'user_id' not in session:
            flash('Please login to continue', 'info')
            return redirect(url_for('login'))
        
        # Retrieve user from the database
        user = User.query.get(session['user_id'])
        
        # Check if user is None
        if user is None:
            flash('User not found. Please login again.', 'warning')
            return redirect(url_for('login'))
        
        # Check if the user is a sponsor
        if user.role != 'sponsor':
            flash('You are not authorized to access this page', 'warning')
            return redirect(url_for('login'))
        
        return func(*args, **kwargs)
    return inner

def influencer_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'info')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'influencer':
            flash('You are not authorized to access this page', 'warning')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return inner

    

    
@app.route('/admin_login', methods=["POST", "GET"])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        name = request.form.get('name')
        role = request.form.get('role')
        password = request.form.get('password')
        confirmpassword = request.form.get('confirmpassword')
        email = request.form.get('email')
        age = request.form.get('age')

        if not username or not name or not role or not password or not email or not age:
            flash("Please fill out all the fields!", 'warning')
            return redirect(url_for('admin_login'))
        if password != confirmpassword:
            flash("Passwords do not match", 'warning')
            return redirect(url_for('admin_login'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists", 'danger')
            return redirect(url_for('admin_login'))
        if User.query.filter_by(email=email).first():
            flash("Email already exists", 'danger')
            return redirect(url_for('admin_login'))

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, name=name, role=role, passhash=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        adminDetails = Admin(admin_name=name, age=age, user_id=new_user.id)
        db.session.add(adminDetails)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('admin_login.html')



# Sponsor Registration Route
@app.route('/sponsor_login', methods=["POST", "GET"])
def sponsor_login():
    
    if request.method == "POST":
        username = request.form.get('username')
        name = request.form.get('name')
        password = request.form.get('password')
        role = request.form.get('role')
        confirmpassword = request.form.get('confirmpassword')
        industry = request.form.get('industry')
        establishment = request.form.get('establishment')
        email = request.form.get('email')
        budget = request.form.get('budget')

        establishment_date = None
        if establishment:
            try:
                establishment_date = datetime.strptime(establishment, '%Y-%m-%d').date()
            except ValueError:
                flash("Invalid date format", 'warning')
                return redirect(url_for('sponsor_login'))

        if not username or not name or not role or not password or not industry or not budget or not establishment or not email:
            flash("Please fill out all the fields!", 'warning')
            return redirect(url_for('sponsor_login'))
        if password != confirmpassword:
            flash("Passwords do not match", 'warning')
            return redirect(url_for('sponsor_login'))

        user_by_name = User.query.filter_by(username=username).first()
        user_by_email = User.query.filter_by(email=email).first()
        user_by_company_name = User.query.filter_by(name=name).first()
        if user_by_company_name:
            flash('Company name already exists', 'danger')
            return redirect(url_for('sponsor_login'))
        if user_by_name:
            flash("Username already exists", 'danger')
            return redirect(url_for('sponsor_login'))
        if user_by_email:
            flash("Email already exists", 'danger')
            return redirect(url_for('sponsor_login'))

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, name=name, role=role, passhash=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        # Check if an influencer without a sponsor exists and link it
        existing_influencer = Influencer.query.filter_by(sponsor_id=None).first()

        sponsorDetails = Sponsor(
            sponsor_name=name,
            industry=industry,
            budget=budget,
            establishment=establishment_date,
            user_id=new_user.id
        )

        if existing_influencer:
            sponsorDetails.influencer_id = existing_influencer.id
            existing_influencer.sponsor_id = sponsorDetails.id
            db.session.add(existing_influencer)  # Update the influencer with the sponsor ID

        db.session.add(sponsorDetails)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('sponsor_login.html')


# Influencer Registration Route
@app.route('/influencer_login', methods=["POST", "GET"])
def influencer_login():
    if request.method == "POST":
        username = request.form.get('username')
        name = request.form.get('name')
        role = request.form.get('role')
        password = request.form.get('password')
        confirmpassword = request.form.get('confirmpassword')
        category = request.form.get('category')
        age = request.form.get('age')
        email = request.form.get('email')
        niche = request.form.get('niche')
        reach = request.form.get('reach')

        if not username or not name or not role or not password or not category or not age or not email or not niche or not reach:
            flash("Please fill out all the fields!", 'warning')
            return redirect(url_for('influencer_login'))
        if password != confirmpassword:
            flash("Passwords do not match", 'warning')
            return redirect(url_for('influencer_login'))

        user_by_name = User.query.filter_by(username=username).first()
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_name:
            flash("Username already exists", 'danger')
            return redirect(url_for('influencer_login'))
        if user_by_email:
            flash("Email already exists", 'danger')
            return redirect(url_for('influencer_login'))

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, name=name, role=role, passhash=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()

        # Check if a sponsor without an influencer exists and link it
        existing_sponsor = Sponsor.query.filter_by(influencer_id=None).first()

        influencerDetails = Influencer(
            influencer_name=name,
            category=category,
            age=age,
            niche=niche,
            reach=reach,
            user_id=new_user.id
        )

        if existing_sponsor:
            influencerDetails.sponsor_id = existing_sponsor.id
            existing_sponsor.influencer_id = influencerDetails.id
            db.session.add(existing_sponsor)  # Update the sponsor with the influencer ID

        db.session.add(influencerDetails)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('influencer_login.html')

@app.route('/admin_logout', methods=["POST", "GET"])
def admin_logout():
    if request.method == "GET":
        session.pop('user_id', None)  # Assuming 'user_id' is stored in session
    flash('You are logged out now', 'info')
    return redirect(url_for('login'))

from plots import create_charts
@app.route('/admin', methods=["POST", "GET"])
@admin_required
def admin():
    if request.method == "GET":
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        
        if user is None:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
        admin = Admin.query.filter_by(user_id=user_id).first()
        
        if not admin:
            flash('No admin found for this user', 'danger')
            return redirect(url_for('admin_login'))
        
        # Fetch data for charts
        active_influencer = Influencer.query.filter_by(is_active=1).count()
        active_sponsor = Sponsor.query.filter_by(is_active=1).count()
        inactive_influencer = Influencer.query.filter_by(is_active=0).count()
        inactive_sponsor = Sponsor.query.filter_by(is_active=0).count()
        
        active_users_count = active_influencer + active_sponsor
        inactive_users_count = inactive_influencer + inactive_sponsor
        
        
        public_campaigns_count = Campaign.query.filter_by(visibility="public").count()
        private_campaigns_count = Campaign.query.filter_by(visibility="private").count()
        total_ad_requests = AddRequest.query.count()
        
        requets_send_by_sponsors_status = {
            'Pending': Notification.query.filter_by(status='Pending').count(),
            'Approved': Notification.query.filter_by(status='Accepted').count(),
            'Rejected': Notification.query.filter_by(status='Rejected').count()
        }
        requets_send_by_influencers_status = {
            'Pending': SponsorNotification.query.filter_by(status='Pending').count(),
            'Approved': SponsorNotification.query.filter_by(status='Accepted').count(),
            'Rejected': SponsorNotification.query.filter_by(status='Rejected').count()
        }
        flagged_entities = {
            'Flagged Sponsors': Sponsor.query.filter_by(is_active=False).count(),
            'Flagged Influencers': Influencer.query.filter_by(is_active=False).count(),
            'Flagged Campaigns': Campaign.query.filter_by(is_active=False).count(),
            'Flagged Ad Requests': AddRequest.query.filter_by(is_active=False).count()
        }

        total_influencer = Influencer.query.count()
        total_sponsor = Sponsor.query.count()
        total_campaigns = Campaign.query.count()
        total_ad_requests = AddRequest.query.count()
        # Generate charts with real data
        create_charts(active_users_count,total_influencer,total_sponsor, total_campaigns,total_ad_requests,inactive_users_count, public_campaigns_count, private_campaigns_count,requets_send_by_sponsors_status, requets_send_by_influencers_status, flagged_entities)

        
        sponsor_notifications = SponsorNotification.query.all()
        notifications = Notification.query.all()
        sponsors = Sponsor.query.all()
        sponsor = Sponsor.query.first()
        influencers = Influencer.query.all()
        influencer = Influencer.query.first()
        campaigns = Campaign.query.all()
        ad_requests = AddRequest.query.all()
        
        flagged_sponsors = Sponsor.query.filter_by(is_active=0).all()
        flagged_influencers = Influencer.query.filter_by(is_active=0).all()
        flagged_campaigns = Campaign.query.filter_by(is_active=0).all()
        flagged_ad_requests = AddRequest.query.filter_by(is_active=0).all()
        
        total_flagged_sponsors = Sponsor.query.filter_by(is_active=0).count()
        total_flagged_influencers = Influencer.query.filter_by(is_active=0).count()
        total_flagged_campaigns = Campaign.query.filter_by(is_active=0).count()
        total_flagged_ad_requests = AddRequest.query.filter_by(is_active=0).count()
        total_flagged_entities = (total_flagged_sponsors +
                          total_flagged_influencers +
                          total_flagged_campaigns +
                          total_flagged_ad_requests)
        
        return render_template('admin.html',
                               user=user,
                               admin=admin,
                               total_influencer=total_influencer,
                               total_sponsor=total_sponsor,
                               total_campaigns=total_campaigns,
                               total_ad_requests=total_ad_requests,
                               sponsor_notifications=sponsor_notifications,
                               sponsors=sponsors,
                               notifications=notifications,
                               influencers=influencers,
                               campaigns=campaigns,
                               ad_requests=ad_requests,
                               influencer=influencer,
                               sponsor=sponsor,
                               total_flagged_entities=total_flagged_entities,
                               flagged_sponsors=flagged_sponsors,
                               flagged_influencers=flagged_influencers,
                               flagged_campaigns=flagged_campaigns,
                               flagged_ad_requests=flagged_ad_requests,
                               active_vs_inactive_img='Images/active_vs_inactive.png',
                               campaign_visibility_img='Images/campaign_visibility.png',
                               requests_send_by_sponsors_status='Images/ad_requests_by_status.png',
                               requests_send_by_influencers_status='Images/ad_requests_by_status.png',
                               flagged_entities_img='Images/flagged_entities.png',
                               comparison1_img='Images/comparison1.png',
                               comparison2_img='Images/comparison2.png')



# for influencer 

@app.route('/click_view_campaign/<int:campaign_id>')
def view_campaign(campaign_id):
    mark_notification_as_read(campaign_id, 'campaign')  # For Notification model
    return redirect(url_for('campaign_details', campaign_id=campaign_id))

@app.route('/click_view_ad_request/<int:ad_request_id>')
def view_ad_request(ad_request_id):
    mark_notification_as_read(ad_request_id, 'ad_request')  # For Notification model
    return redirect(url_for('ad_request_details', ad_request_id=ad_request_id))

# for sponsor

@app.route('/click_view_sponsor_campaign/<int:campaign_id>')
def view_sponsor_campaign(campaign_id):
    mark_sponsor_notification_as_read(campaign_id, 'campaign')  # For SponsorNotification model
    return redirect(url_for('campaign_details', campaign_id=campaign_id))

@app.route('/click_view_sponsor_ad_request/<int:ad_request_id>')
def view_sponsor_ad_request(ad_request_id):
    mark_sponsor_notification_as_read(ad_request_id, 'ad_request')  # For SponsorNotification model
    return redirect(url_for('ad_request_details', ad_request_id=ad_request_id))

@app.route('/influencer', methods=["POST", "GET"])
@influencer_required
def influencer():
    user_id = session.get('user_id')
    
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    influencer = Influencer.query.filter_by(user_id=user_id).first()

    if not influencer:
        flash('No influencer found for this user', 'danger')
        return redirect(url_for('influencer_login'))

    # Fetch all received requests from sponsors
    received_requests = Notification.query.filter_by(receiver_id=user_id).all()
    for received_request in received_requests:
        sender_name = received_request.user.username if received_request.user else 'Unknown'
        campaign_name = received_request.campaign.campaign_name if received_request.campaign else 'Unknown campaign'
        received_request.message = f"New ad request from {sender_name} for campaign '{campaign_name}'"

    # Fetch all sent requests to sponsors
    sent_requests = SponsorNotification.query.filter_by(user_id=user_id).all()
    for sent_request in sent_requests:
        receiver_name = sent_request.receiver.username if sent_request.receiver else 'Unknown'
        campaign_name = sent_request.campaign.campaign_name if sent_request.campaign else 'Unknown campaign'
        sent_request.message = f"You sent an ad request to {receiver_name} for campaign '{campaign_name}'"

    unread_notifications = sum(1 for request in received_requests if not request.is_read)

    return render_template(
        'influencer.html',
        user=user,
        influencer=influencer,
        received_requests=received_requests,
        sent_requests=sent_requests,
        unread_notifications=unread_notifications
    )


@app.route('/sponsor', methods=["POST", "GET"])
@sponsor_required
def sponsor():
    if request.method == "GET":
        user_id = session.get('user_id')
        
        user = User.query.get(user_id)
        if user is None:
            flash('User not found', 'danger')
            return redirect(url_for('login'))
        
        sponsors = Sponsor.query.filter_by(user_id=user_id).first()
        if not sponsors:
            flash('No sponsors found for this user', 'danger')
            return redirect(url_for('sponsor_login'))

        # Fetch notifications sent by the sponsor
        notifications = Notification.query.filter_by(user_id=user_id).all()
        for notification in notifications:
            receiver_name = notification.receiver.username if notification.receiver else 'Unknown'
            campaign_name = notification.campaign.campaign_name if notification.campaign else 'Unknown campaign'
            notification.message = f"You sent an ad request to {receiver_name} for campaign '{campaign_name}'"

        # Fetch all received notifications for this sponsor
        sponsor_notifications = SponsorNotification.query.filter_by(receiver_id=user_id).all()
        for sponsor_notification in sponsor_notifications:
            sender_name = sponsor_notification.user.username if sponsor_notification.user else 'Unknown'
            campaign_name = sponsor_notification.campaign.campaign_name if sponsor_notification.campaign else 'Unknown campaign'
            sponsor_notification.message = f"New ad request from {sender_name} for campaign '{campaign_name}'"

        unread_notifications = sum(1 for notification in sponsor_notifications if not notification.is_read)

        campaigns = Campaign.query.filter_by(sponsor_id=sponsors.id).all()
        public_campaigns = Campaign.query.filter_by(sponsor_id=sponsors.id, visibility='public').all()
        ad_requests = []
        for campaign in campaigns:
            ad_requests.extend(AddRequest.query.filter_by(campaign_id=campaign.id).all())

        return render_template('sponsor.html', 
                               user=user, 
                               sponsors=sponsors, 
                               campaigns=campaigns, 
                               ad_requests=ad_requests, 
                               public_campaigns=public_campaigns,
                               unread_notifications=unread_notifications, 
                               sponsor_notifications=sponsor_notifications, 
                               notifications=notifications)

    
@app.route('/click_view_influencer/<int:influencer_id>')
def click_view_influencer(influencer_id):
    print(f'This is the influencer id, {influencer_id} ')
    influencer = Influencer.query.filter_by(user_id=influencer_id).first()
    print(f'influencer details')
    if not influencer:
        flash('Influencer not found', 'danger')
        return redirect(url_for('sponsor'))
    
    return render_template('view_influencer.html', influencer=influencer)



@app.route('/click_view_sponsor/<int:sponsor_id>')
def click_view_sponsor(sponsor_id):
    print(f'This is the sponsor id, {sponsor_id} ')
    sponsor = Sponsor.query.filter_by(user_id=sponsor_id).first()
    if not sponsor:
        flash('Sponsor not found', 'danger')
        return redirect(url_for('influencer'))
    return render_template('view_sponsor.html',sponsor=sponsor)

@app.route('/create_campaigns', methods=["POST", "GET"])
def create_campaigns():
    if request.method == 'POST':
        user_id = session.get('user_id')
        
        if user_id is None:
            flash('User not logged in', 'danger')
            return redirect(url_for('login'))
        
        # Ensure the logged-in user is a sponsor
        user = User.query.get(user_id)
        if user is None or user.role != 'sponsor':
            flash('Only sponsors can create campaigns.', 'danger')
            return redirect(url_for('sponsor'))

        # Fetch the sponsor associated with the user_id
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        
        if sponsor is None:
            flash('Sponsor not found', 'danger')
            return redirect(url_for('sponsor'))
        
        sponsor_id = sponsor.id
        sponsor_name = sponsor.sponsor_name
        
        # Retrieve form data
        campaign_name = request.form.get('name')
        description = request.form.get('description')
        start_date = request.form.get('starting_date')
        end_date = request.form.get('ending_date')
        budget = request.form.get('budget')
        visibility = request.form.get('visibility', 'private')
        goals = request.form.get('goals')
        
        existing_campaign = Campaign.query.filter_by(campaign_name=campaign_name).first()
        
        if not campaign_name or not description or not budget or not goals:
            flash('Please fill out all the fields!', 'warning')
            return redirect(url_for('create_campaigns'))

        if existing_campaign:
            flash('A campaign with this name already exists.', 'danger')
            return redirect(url_for('update_campaign', campaign_id=existing_campaign.id))
        
        if not start_date or not end_date:
            flash('Please fill out the date fields!', 'info')
            return redirect(url_for('create_campaigns'))
        
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('create_campaigns'))
        

        # Create new campaign
        new_campaign = Campaign(
            sponsor_id=sponsor_id,
            sponsor_name=sponsor_name,
            campaign_name=campaign_name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            budget=budget,
            visibility=visibility,
            goals=goals
        )
    
        # Add to database
        try:
            db.session.add(new_campaign)
            db.session.commit()
            flash('Campaign created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred: {e}', 'danger')
            print(f"Error occurred: {e}")
        
        return redirect(url_for('sponsor'))
    
    return render_template('add_campaigns.html')




@app.route('/update_campaign/<int:campaign_id>', methods=['GET', 'POST'])
def update_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)

    if request.method == 'POST':
        campaign.campaign_name = request.form.get('name')
        campaign.description = request.form.get('description')
        start_date = request.form.get('starting_date')
        end_date = request.form.get('ending_date')
        campaign.budget = request.form.get('budget')
        campaign.visibility = request.form.get('visibility', 'private')
        campaign.goals = request.form.get('goals')
        
        
        if not campaign.campaign_name or not campaign.description or not campaign.budget or not campaign.goals:
            flash('Please fill out all the fields', 'info')
            return redirect(url_for('create_campaigns'))
        
        if not campaign.start_date or not campaign.end_date:
            flash('Please fill out the date fields!', 'warning')
            return redirect(url_for('update_campaign', campaign_id=campaign_id))
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
            return redirect(url_for('create_campaigns'))

        
        db.session.commit()
        flash('Campaign updated successfully!', 'success')
        return redirect(url_for('sponsor'))

    return render_template('update_campaign.html', campaign=campaign)

@app.route('/delete_campaign/<int:campaign_id>', methods=['POST'])
def delete_campaign(campaign_id):
    # Fetch the campaign to be deleted
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # Fetch and delete only the ad requests that match the campaign ID
    matching_ad_requests = AddRequest.query.filter_by(campaign_id=campaign_id).all()
    for ad_request in matching_ad_requests:
        db.session.delete(ad_request)
    
    # Delete the campaign itself
    db.session.delete(campaign)
    
    try:
        db.session.commit()
        flash('Campaign and associated ad requests deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error occurred while deleting the campaign: {e}', 'danger')
    
    return redirect(url_for('sponsor'))


@app.route('/create_ad_requests', methods=["POST", "GET"])
def create_ad_requests():
    if request.method == 'POST':
        user_id = session.get('user_id')
        
        if user_id is None:
            flash('User not logged in')
            return redirect(url_for('login'))

        # Fetch the sponsor associated with the user_id
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        if sponsor is None:
            flash('Sponsor not found')
            return redirect(url_for('sponsor'))

        # Retrieve form data
        campaign_id = request.form.get('campaign_id')
        message = request.form.get('message')
        requirements = request.form.get('requirements')
        payment = request.form.get('payment')

        # Validate the input data
        if not all([campaign_id, message, requirements, payment]):
            flash("Please fill out all the fields!", 'warning')
            return redirect(url_for('create_ad_requests'))

        # Check if the selected campaign ID exists and belongs to the sponsor
        campaign = Campaign.query.filter_by(id=campaign_id, sponsor_id=sponsor.id).first()
        if not campaign:
            flash("Selected campaign does not exist or doesn't belong to you!", 'danger')
            return redirect(url_for('create_ad_requests'))

        # Automatically retrieve the first influencer associated with the sponsor
        influencer = Influencer.query.filter_by(sponsor_id=sponsor.id).first()
        if influencer is None:
            influencer = Influencer.query.first()  # Or any other fallback logic
            if influencer is None:
                flash('No influencer found for this sponsor or globally.')
                return redirect(url_for('sponsor'))

        # Create new Ad Request
        new_ad_request = AddRequest(
            campaign_id=campaign.id,
            influencer_id=influencer.id,
            campaign_name=campaign.campaign_name,
            message=message,
            requirements=requirements,
            payment_amount=payment
        )
    
        # Add to database
        try:
            db.session.add(new_ad_request)
            db.session.commit()
            flash('Ad request created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred: {e}', 'danger')
            print(f"Error occurred: {e}")
        
        return redirect(url_for('sponsor'))
    
    # Handle GET request
    user_id = session.get('user_id')
    if user_id is None:
        flash('User not logged in')
        return redirect(url_for('login'))

    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    if sponsor is None:
        flash('Sponsor not found')
        return redirect(url_for('sponsor'))

    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    
    return render_template('add_ad_requests.html', campaigns=campaigns)




@app.route('/update_ad_requests/<int:ad_request_id>', methods=['GET', 'POST'])
def update_ad_requests(ad_request_id):
    ad_request = AddRequest.query.get_or_404(ad_request_id)

    if request.method == 'POST':
        # Fetch form data
        campaign_id = request.form.get('campaign_id')
        message = request.form.get('message')
        requirements = request.form.get('requirements')
        payment = request.form.get('payment')

        # Validate form data
        if not all([campaign_id, message, requirements, payment]):
            flash("Please fill out all fields!", 'warning')
            return redirect(url_for('update_ad_requests', ad_request_id=ad_request_id))

        # Find the selected campaign
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            flash("Selected campaign does not exist.", 'danger')
            return redirect(url_for('update_ad_requests', ad_request_id=ad_request_id))

        # Update ad request
        ad_request.campaign_id = campaign.id
        ad_request.campaign_name = campaign.campaign_name
        ad_request.message = message
        ad_request.requirements = requirements
        ad_request.payment_amount = float(payment)  # Convert to float
        
        try:
            db.session.commit()
            flash('Ad request updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred: {e}', 'danger')
            print(f"Error occurred: {e}")
            
        
        return redirect(url_for('sponsor'))

    # Handle GET request
    user_id = session.get('user_id')
    if user_id is None:
        flash('User not logged in')
        return redirect(url_for('login'))

    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    if sponsor is None:
        flash('Sponsor not found')
        return redirect(url_for('sponsor'))

    # Fetch campaigns for the dropdown
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
    
    return render_template('update_ad_requests.html', ad_request=ad_request, campaigns=campaigns)



@app.route('/delete_ad_requests/<int:ad_request_id>', methods=['POST'])
def delete_ad_requests(ad_request_id):
    ad_request= AddRequest.query.get_or_404(ad_request_id)
    db.session.delete(ad_request)
    db.session.commit()
    flash('Ad requests deleted successfully!', 'success')
    return redirect(url_for('sponsor'))



@app.route('/search_influencer', methods=['GET'])
def search_influencer():
    user_id = session.get('user_id')
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    sponsor_id = sponsor.id  # Get the sponsor ID from the session
    
    
    # Debugging: Print sponsor ID to console
    print("Sponsor ID:", sponsor_id)

    influencers = Influencer.query.all()
    private_campaigns = Campaign.query.filter_by(visibility='private', sponsor_id=sponsor_id).all()
    
    # Debugging: Print private campaigns to console
    print("Private Campaigns:", private_campaigns)
    
    campaign_ids = [campaign.id for campaign in private_campaigns]
    ad_requests = AddRequest.query.filter(AddRequest.campaign_id.in_(campaign_ids)).all()
    
    # Debugging: Print ad requests to console
    print("Ad Requests:", ad_requests)
    
    return render_template('search_influencer.html', influencers=influencers, private_campaigns=private_campaigns, ad_requests=ad_requests)

@app.route('/view_campaign/<int:campaign_id>')
def campaign_details(campaign_id):
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        flash('No campaign exists')
        return redirect(url_for('influencer'))  # Handle not found cases
    return render_template('campaign_details.html', campaign=campaign)

@app.route('/view_ad_request/<int:ad_request_id>')
def ad_request_details(ad_request_id):
    ad_request = AddRequest.query.get_or_404(ad_request_id)
    if not ad_request:
        flash('No ad request exists')
        return redirect(url_for('influencer'))  # Handle not found cases
    return render_template('ad_request_details.html', ad_request=ad_request)


@app.route('/update_influencer_profile/<int:user_id>', methods=["POST", "GET"])
def update_influencer_profile(user_id):
    user = User.query.get_or_404(user_id)
    influencer = Influencer.query.filter_by(user_id=user_id).first_or_404()  # Assuming user_id is a foreign key in Influencer
    
    if request.method == "POST":
        if user.role == "influencer":
            # Update User table fields
            user.email = request.form.get('email')
            user.username = request.form.get('username')
            
            # Update Influencer table fields
            influencer.category = request.form.get('category')
            
            # Handle 'reach' field with default value if not provided
            reach = request.form.get('reach')
            if reach:
                try:
                    influencer.reach = int(reach)  # Convert to integer
                except ValueError:
                    flash('Invalid value for reach. It must be an integer.', 'danger')
                    return redirect(url_for('update_influencer_profile', user_id=user.id))
            else:
                influencer.reach = 0  # Set default value or handle as needed

            # Commit the changes to the database
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('influencer', user_id=user.id))  # Redirect to profile view or other page

    return render_template('update_influencer_profile.html', user=user, influencer=influencer)



@app.route('/update_sponsor_profile/<int:user_id>', methods=["POST", "GET"])
def update_sponsor_profile(user_id):
    user = User.query.get_or_404(user_id)
    sponsor = Sponsor.query.filter_by(user_id=user_id).first_or_404()  # Adjust model name if needed

    if request.method == "POST":
        if user.role == "sponsor":
            # Update User table fields
            user.email = request.form.get('email')
            user.username = request.form.get('username')
            
            # Update Sponsor table fields
            industry = request.form.get('industry')
            if industry:
                sponsor.industry = industry
            else:
                flash('Industry field cannot be empty.', 'danger')
                return redirect(url_for('update_sponsor_profile', user_id=user.id))

            # Handle 'budget' field with default value if not provided
            try:
                budget = request.form.get('budget')
                if budget:
                    sponsor.budget = float(budget)  # Convert to integer
                else:
                    sponsor.budget = 0  # Set default value
            except ValueError:
                flash('Invalid value for budget. It must be an integer.', 'danger')
                return redirect(url_for('update_sponsor_profile', user_id=user.id))

            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('sponsor', user_id=user.id))  # Redirect to profile view or other page

    return render_template('update_sponsor_profile.html', user=user, sponsor=sponsor)



@app.route('/sponsor_logout', methods=["POST", "GET"])
def sponsor_logout():
    if request.method == "GET":
        session.pop('user_id', None)  # Assuming 'user_id' is stored in session
        flash('You are logged out now', 'info')
        return redirect(url_for('login'))


@app.route('/influencer_logout', methods=["POST", "GET"])
def influencer_logout():
    if request.method == "GET":
        flash('You are logged out now', 'info')
        return redirect(url_for('login'))
   



@app.route('/search_campaigns')
def search_campaigns():
    influencer_user_id = session.get('user_id')
    
    if not influencer_user_id:
        flash('Please log in to search campaigns.', 'warning')
        return redirect(url_for('login'))
    
    influencer = Influencer.query.filter_by(user_id=influencer_user_id).first()
    
    if not influencer:
        flash('Influencer not found.', 'warning')
        return redirect(url_for('login'))

    # Fetch all public campaigns regardless of the sponsor
    campaigns = Campaign.query.filter_by(visibility='public').all()
    entries = SetCampaignAdRequest.query.all()

    return render_template('search_campaigns.html', influencer=influencer, entries=entries, campaigns=campaigns)


@app.route('/see_public_campaigns', methods=["GET", "POST"])
@sponsor_required
def see_public_campaigns():
    if request.method == "POST":
        user_id = session.get('user_id')
        campaign_id = request.form.get('campaign_id')
        ad_request_id = request.form.get('ad_request_id')
        sponsor = Sponsor.query.filter_by(user_id=user_id).first()
        sponsor_id = sponsor.id  # Get the sponsor ID from the session

        # Fetch the selected campaign and ad request
        campaign = Campaign.query.get(campaign_id)
        ad_request = AddRequest.query.get(ad_request_id)

        if not campaign or not ad_request:
            flash('Selected campaign or ad request not found.', 'danger')
            return redirect(url_for('sponsor'))

        # Check if entry already exists
        existing_entry = SetCampaignAdRequest.query.filter_by(
            campaign_id=campaign_id, ad_request_id=ad_request_id, sponsor_id=sponsor_id
        ).first()
        if existing_entry:
            flash('Entry already exists.', 'danger')
        else:
            # Create and add the entry to SetCampaignAdRequest
            entry = SetCampaignAdRequest(
                campaign_id=campaign_id, ad_request_id=ad_request_id, sponsor_id=sponsor_id
            )
            db.session.add(entry)
            db.session.commit()
            flash('Entry added successfully.', 'success')

    # Fetch all campaigns and ad requests for the current sponsor only
    user_id = session.get('user_id')
    sponsor = Sponsor.query.filter_by(user_id=user_id).first()
    sponsor_id = sponsor.id
    campaigns = Campaign.query.filter_by(sponsor_id=sponsor_id, visibility='public').all()  # Only public campaigns
    ad_requests = AddRequest.query.all()

    # Fetch all entries related to the current sponsor
    entries = SetCampaignAdRequest.query.filter_by(sponsor_id=sponsor_id).all()

    return render_template('see_public_campaigns.html', campaigns=campaigns, ad_requests=ad_requests, entries=entries)



# See sponsor campaigns



@app.route('/delete_set_entry/<int:entry_id>', methods=["POST"])
@sponsor_required
def delete_set_entry(entry_id):
    entry = SetCampaignAdRequest.query.get(entry_id)
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash('Entry deleted successfully.', 'success')
    else:
        flash('Entry not found.', 'danger')
    return redirect(url_for('see_public_campaigns'))

@app.route('/send_notification_to_sponsor', methods=['POST'])
def send_notification_to_sponsor():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.role != 'influencer':
        return redirect(url_for('login'))

    campaign_id = request.form.get('campaign_id')
    ad_request_id = request.form.get('ad_request_id')
    influencer = Influencer.query.filter_by(user_id=session['user_id']).first()

    if not influencer:
        flash('Influencer not found.', 'warning')
        return redirect(url_for('search_campaigns'))

    campaign = Campaign.query.get(campaign_id) if campaign_id else None
    ad_request = AddRequest.query.get(ad_request_id) if ad_request_id else None

    if not campaign and not ad_request:
        flash('Campaign or Ad Request not found.', 'warning')
        return redirect(url_for('search_campaigns'))

    receiver_id = request.form.get('sponsor_id')  # Use the correct sponsor's user_id

    if not receiver_id:
        flash('Sponsor not found.', 'warning')
        return redirect(url_for('search_campaigns'))

    notification = SponsorNotification(
        user_id=influencer.user_id,
        receiver_id=receiver_id,
        campaign_id=campaign.id if campaign else None,
        ad_request_id=ad_request.id if ad_request else None,
        message=f"New ad request from influencer {user.username}. Check out the details!",
        is_read=False
    )

    db.session.add(notification)
    db.session.commit()

    flash('Notification sent to sponsor.', 'success')
    return redirect(url_for('search_campaigns'))


@app.route('/send_notification', methods=['POST'])
def send_notification():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user.role != 'sponsor':
        return redirect(url_for('login'))

    influencer_id = request.form.get('influencer_id')
    campaign_id = request.form.get('campaign_id')
    ad_request_id = request.form.get('ad_request_id')

    influencer = Influencer.query.get(influencer_id)
    campaign = Campaign.query.get(campaign_id) if campaign_id else None
    ad_request = AddRequest.query.get(ad_request_id) if ad_request_id else None

    if not influencer:
        flash('Influencer not found.', 'warning')
        return redirect(url_for('search_influencer'))

    if not campaign and not ad_request:
        flash('Campaign or Ad Request not found.', 'warning')
        return redirect(url_for('search_influencer'))

    sponsor = Sponsor.query.filter_by(user_id=session['user_id']).first()

    notification = Notification(
        user_id=sponsor.user_id,  # The sponsor's user_id
        receiver_id=influencer.user_id,  # The influencer's user_id
        campaign_id=campaign.id if campaign else None,
        ad_request_id=ad_request.id if ad_request else None,
        message=f'Notification sent to influencer {influencer.influencer_name}.',
        is_read=False
    )
    db.session.add(notification)
    db.session.commit()

    flash(f'Notification sent to {influencer.influencer_name}.', 'success')
    return redirect(url_for('search_influencer'))



# @app.route('/negotiate/')
# def negotiate():
#     return render_template('negotiate.html')

# @app.route('/fetch_messages')
# def fetch_messages():
#     user_id = request.args.get('user_id')
#     # Fetch messages from the database
#     messages = get_messages(user_id)  # Implement this function to get messages from the database
#     return jsonify({'messages': messages})

# @app.route('/send_message', methods=['POST'])
# def send_message():
#     data = request.json
#     user_id = data['user_id']
#     text = data['text']
#     # Save the message to the database
#     success = save_message(user_id, text)  # Implement this function to save the message
#     return jsonify({'success': success})


@app.route('/update_notification_status/<int:notification_id>/<string:status>', methods=['POST'])
def update_notification_status(notification_id, status):
    notification = Notification.query.get(notification_id)
    if notification:
        notification.status = status
        flash(f'Request, {notification.status} ', 'info')
        db.session.commit()
    return redirect(request.referrer)


@app.route('/update_sponsor_notification_status/<int:notification_id>/<string:status>', methods=['POST'])
def update_sponsor_notification_status(notification_id, status):
    notification = SponsorNotification.query.get(notification_id)
    if notification:
        notification.status = status
        flash(f'Request, {notification.status} ', 'info')
        db.session.commit()
    return redirect(request.referrer)




@app.route('/view_influencer/<int:influencer_id>')
def view_influencer(influencer_id):
    influencer = Influencer.query.get_or_404(influencer_id)
    return render_template('influencer_details.html', influencer=influencer)

@app.route('/view_sponsor/<int:sponsor_id>')
def view_sponsor(sponsor_id):
    sponsor = Sponsor.query.get_or_404(sponsor_id)
    return render_template('sponsor_details.html', sponsor=sponsor)



@app.route('/flag/<item_type>/<int:item_id>', methods=['POST'])
def flag(item_type, item_id):
    item = get_item(item_type, item_id)
    if item:
        item.is_active = False
        db.session.commit()
        flash(f'{item_type.capitalize()} has been flagged.', 'success')
    else:
        flash(f'{item_type.capitalize()} not found.', 'danger')
    return redirect(url_for('admin'))

@app.route('/unflag/<item_type>/<int:item_id>', methods=['POST'])
def unflag(item_type, item_id):
    item = get_item(item_type, item_id)
    if item:
        item.is_active = True
        db.session.commit()
        flash(f'{item_type.capitalize()} has been unflagged.', 'success')
    else:
        flash(f'{item_type.capitalize()} not found.', 'danger')
    return redirect(url_for('admin'))

def get_item(item_type, item_id):
    if item_type == 'influencer':
        return Influencer.query.get(item_id)
    elif item_type == 'sponsor':
        return Sponsor.query.get(item_id)
    elif item_type == 'campaign':
        return Campaign.query.get(item_id)
    elif item_type == 'ad_request':
        return AddRequest.query.get(item_id)
    else:
        return None

@app.route('/disable_sponsor_negotiation', methods=['POST', 'GET'])
def disable_sponsor_negotiation():
    flash("It's disable now!", 'info')
    return redirect(url_for('sponsor'))

@app.route('/disable_influencer_negotiation', methods=['POST', 'GET'])
def disable_influencer_negotiation():
    flash("It's disable now!", 'info')
    return redirect(url_for('influencer'))
