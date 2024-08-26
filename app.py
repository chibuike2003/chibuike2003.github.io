from datetime import datetime, timedelta
from enum import Enum  # Add this import statement
import os
import random
import string

from flask import Flask, render_template, redirect, flash, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, FileField, TextAreaField, DateField, SelectField
from wtforms.validators import InputRequired, Email, EqualTo, Length
from flask_wtf.file import FileAllowed

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/holyghost_agenda'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static/uploads')  # Path to uploads folder
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif', 'mp4', 'avi'}
db = SQLAlchemy(app)
mail = Mail(app)

# Ensure the uploads folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Database model definitions and other code...

# Database model for the user
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    profile_picture = db.Column(db.String(150), nullable=True)  # Path to the saved file
    house_address = db.Column(db.String(100), nullable=False)
    birthday = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(6), nullable=False)
    comment = db.Column(db.String(200), nullable=True)
    password = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)
from datetime import datetime
class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    media = db.Column(db.String(255), nullable=True)
    user = db.relationship('User', backref=db.backref('blogs', lazy=True))

    def __repr__(self):
        return f'<Blog {self.id}>'
class RequestStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(10), default='pending')  # "pending", "accepted", "rejected"
    timestamp = db.Column(db.DateTime, default=db.func.now())

    from_user = db.relationship('User', foreign_keys=[from_user_id], backref='sent_requests')
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref='received_requests')
    

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)  # E.g., "signup", "login", "logout"
    timestamp = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref=db.backref('activities', lazy=True))

    def __repr__(self):
        return f'<UserActivity {self.activity_type} by User {self.user_id} at {self.timestamp}>'

# Track user activity function
def track_user_activity(user, activity_type):
    activity = UserActivity(user_id=user.id, activity_type=activity_type, timestamp=db.func.now())
    db.session.add(activity)
    db.session.commit()
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable in case the user is not logged in
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())  # Automatically add a timestamp when the message is created

    user = db.relationship('User', backref=db.backref('contacts', lazy=True))

    def __repr__(self):
        return f'<Contact {self.id} from {self.email}>'
class Testimony(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now()) 
    user = db.relationship('User', backref=db.backref('Help', lazy=True))
class Help(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now()) 
    user = db.relationship('User', backref=db.backref('testimonies', lazy=True))

# Form for user signup
class SignupForm(FlaskForm):
    firstname = StringField('First Name', validators=[InputRequired(), Length(min=2, max=50)])
    lastname = StringField('Last Name', validators=[InputRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=25)])
    phone_number = StringField('Phone Number', validators=[InputRequired(), Length(min=10, max=15)])
    profile_picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    house_address = StringField('House Address', validators=[InputRequired()])
    birthday = DateField('Birthday', validators=[InputRequired()])
    gender = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female')], validators=[InputRequired()])
    comment = TextAreaField('Comment', validators=[Length(max=200)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
class CommentForm(FlaskForm):
    message = TextAreaField('Message', validators=[InputRequired(), Length(min=1, max=500)])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        # Check if user already exists
        existing_user_by_email = User.query.filter_by(email=form.email.data).first()
        existing_user_by_username = User.query.filter_by(username=form.username.data).first()

        if existing_user_by_email or existing_user_by_username:
            flash('Email or Username already taken.', 'danger')
            return redirect(url_for('signup'))

        profile_picture_filename = None
        if form.profile_picture.data:
            filename = secure_filename(form.profile_picture.data.filename)
            profile_picture_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.profile_picture.data.save(profile_picture_filename)

        new_user = User(
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            email=form.email.data,
            username=form.username.data,
            phone_number=form.phone_number.data,
            profile_picture=profile_picture_filename,
            house_address=form.house_address.data,
            birthday=form.birthday.data,
            gender=form.gender.data,
            comment=form.comment.data,
            password=generate_password_hash(form.password.data)
        )

        db.session.add(new_user)
        db.session.commit()

        # Track signup activity
        track_user_activity(new_user, 'signup')

        flash('Thank you for signing up!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('signup.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch user information from the database
    user = User.query.get(session['user_id'])
    latest_blogs = Blog.query.order_by(Blog.id.desc()).limit(7).all()
    testimonies = Testimony.query.all()

    # Fetch friend requests received by the user (only requests sent to this user)
    received_requests = FriendRequest.query.filter_by(to_user_id=user.id, status='pending').all()

    # Fetch friend requests sent by the user (only requests the user sent)
    sent_requests = FriendRequest.query.filter_by(from_user_id=user.id).all()

    if user:
        return render_template(
            'dashboard.html', 
            user=user, 
            latest_blogs=latest_blogs, 
            sent_requests=sent_requests, 
            received_requests=received_requests,
            testimonies=testimonies
        )

    return redirect(url_for('login'))

@app.route('/membership_form')
def membership_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch user information from the database
    user = User.query.get(session['user_id'])

    # Ensure the user is passed to the template
    if user:
        return render_template('membership form.html', user=user)  # Pass the entire user object

    # If no user is found, redirect to login
    return redirect(url_for('login'))


@app.route('/help', methods=['GET', 'POST'])
def help():
    if 'user_id' not in session:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        message = request.form.get('message')
        
        if not message:
            flash('Message is required.', 'danger')
            return redirect(url_for('help'))

        try:
            user = User.query.get(session['user_id'])
            new_testimony = Help(user_id=user.id, message=message)
            db.session.add(new_testimony)
            db.session.commit()

            flash('Thank you for your message, we will get back to you as soon as possible', 'success')
        except Exception as e:
            flash('An error occurred while submitting your feedback. Please try again.', 'danger')

        return redirect(url_for('help'))

    # Fetch the user if logged in
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])

    # Fetch testimonies
    testimonies = Testimony.query.all()

    return render_template('help.html', testimonies=testimonies, user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']

        user = User.query.filter((User.email == username_or_email) | (User.username == username_or_email)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id  # Log user in

            # Track login activity
            track_user_activity(user, 'login')

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please Put the correct details', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.pop('user_id', None)  # Log user out
    if user_id:
        user = User.query.get(user_id)
        # Track logout activity
        track_user_activity(user, 'logout')

    flash('You have been logged out.', 'success')
    return redirect(url_for('homepage'))

@app.route('/create_blog', methods=['GET', 'POST'])
def create_blog():
    if 'user_id' not in session:
        flash('You must be logged in to create a blog.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        email = request.form.get('email')
        message = request.form.get('message')
        file = request.files.get('media')

        # Validate email
        if email != user.email:
            flash('Email does not match the logged-in user.', 'danger')
            return redirect(url_for('create_blog'))

        # Validate message
        if not message:
            flash('Message is required.', 'danger')
            return redirect(url_for('create_blog'))

        # Validate file
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                flash('Invalid file type. Only images and videos are allowed.', 'danger')
                return redirect(url_for('create_blog'))
        else:
            flash('No file uploaded or file type not allowed.', 'danger')
            return redirect(url_for('create_blog'))

        # Create a new blog entry
        new_blog = Blog(
            user_id=user.id,
            email=email,
            media=filename if file else None,
            message=message
        )
        db.session.add(new_blog)
        db.session.commit()

        flash('Blog post created successfully!', 'success')
        return redirect(url_for('create_blog'))

    return render_template('create blog post.html', user=user)

@app.route('/blog')
def blog_page():
    # Render the blog page; you might need to adjust this based on your actual use case
    return render_template('blog.html')

@app.route('/events_single')
def events_single():
    # Render the blog page; you might need to adjust this based on your actual use case
    return render_template('events-single.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/sermons')
def sermons():
    return render_template('sermons.html')

@app.route('/events')
def events():
    return render_template('events.html')
    
@app.route('/gallery')
def gallery():
    return render_template('gallery.html')

@app.route('/search-blog-results')
def search_results():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    
    # Query all testimonies
    testimonies = Testimony.query.all()
    
    # Query the latest 5 blog posts
    latest_blogs = Blog.query.order_by(Blog.id.desc()).limit(5).all()

    return render_template('search-result.html', user=user, testimonies=testimonies, latest_blogs=latest_blogs)

@app.route('/single post')
def single_post():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    
    # Query all testimonies
    testimonies = Testimony.query.all()
    
    # Query the latest 5 blog posts
    latest_blogs = Blog.query.order_by(Blog.id.desc()).limit(5).all()

    return render_template('single-post.html', user=user, testimonies=testimonies, latest_blogs=latest_blogs)
@app.route('/like/<int:blog_id>', methods=['POST'])
def like_blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    if not blog.likes_count:
        blog.likes_count = 0
    blog.likes_count += 1
    db.session.commit()
    return jsonify({'likes': blog.likes_count})


    return jsonify({'likes': blog.likes_count})
@app.route('/add_comment/<int:blog_id>', methods=['POST'])
def add_comment(blog_id):
    form = CommentForm()
    if form.validate_on_submit():
        blog = Blog.query.get_or_404(blog_id)
        new_comment = Comment(
            fullname=form.fullname.data,
            username=form.username.data,
            email=form.email.data,
            message=form.message.data,
            blog_id=blog.id
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Your comment has been posted!', 'success')
    return redirect(url_for('single_post', blog_id=blog_id))

@app.route('/')
def homepage():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    
    # Query all testimonies
    testimonies = Testimony.query.all()
    
    # Query the latest 5 blog posts
    latest_blogs = Blog.query.order_by(Blog.id.desc()).limit(7).all()

    return render_template('index.html', user=user, testimonies=testimonies, latest_blogs=latest_blogs)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])  # Fetch the logged-in user details
    else:
        user = None

    if request.method == 'POST':
        name = request.form.get('cName')
        email = request.form.get('cEmail')
        topic = request.form.get('cWebsite')
        message = request.form.get('cMessage')

        # Validate the form fields
        if not name or not email or not topic or not message:
            flash('Please fill out all fields.', 'danger')
            return render_template('contact.html', user=user)

        # Save the contact form to the database
        try:
            new_contact = Contact(
                user_id=user.id if user else None,  # If the user is logged in, save their ID
                name=name,
                email=email,
                topic=topic,
                message=message
            )
            db.session.add(new_contact)
            db.session.commit()
            flash('Your message has been sent successfully,we will get in touch with you as soon as possible', 'success')
            return redirect(url_for('contact'))
        except Exception as e:
            print(f"Error occurred: {e}")
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')

    return render_template('contact.html', user=user)
@app.route('/friends')
def friends():
    if 'user_id' not in session:
        flash('You must be logged in to view the Friends page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # Fetch the logged-in user from the database
    all_users = User.query.all()  # Fetch all users from the database
    return render_template('friends.html', user=user, all_users=all_users)

@app.route('/frequently_asked_questions')
def faq():
    if 'user_id' not in session:
        flash('You must be logged in to view the Friends page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # Fetch the logged-in user from the database
    return render_template('faq.html', user=user)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('You must be logged in to view the Friends page.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # Fetch the logged-in user from the database
    return render_template('users-profile.html', user=user)
@app.route('/testimony', methods=['GET', 'POST'])
def testimony():
    if 'user_id' not in session:
        flash('You must be logged in to view this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        message = request.form.get('message')
        
        if not message:
            flash('Message is required.', 'danger')
            return redirect(url_for('testimony'))

        try:
            user = User.query.get(session['user_id'])
            new_testimony = Testimony(user_id=user.id, message=message)
            db.session.add(new_testimony)
            db.session.commit()

            flash('Thank you for your feedback!', 'success')
        except Exception as e:
            flash('An error occurred while submitting your feedback. Please try again.', 'danger')

        return redirect(url_for('testimony'))

    # Fetch the user if logged in
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])

    # Fetch testimonies
    testimonies = Testimony.query.all()
    return render_template('testimonials.html', testimonies=testimonies, user=user)
@app.route('/testimonies')
def testimonies():
    # Query all testimonies
    testimonies = Testimony.query.all()

    # Render the testimon.html template with testimonies
    return render_template('testimony.html', testimonies=testimonies)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with this email address.', 'danger')
            return redirect(url_for('forgot_password'))

        # Generate a random code
        code = ''.join(random.choices(string.digits, k=6))

        # Store the code and expiration time in the database
        expiration_time = datetime.utcnow() + timedelta(minutes=15)  # Code expires in 15 minutes
        reset_entry = PasswordReset(email=email, code=code, expires_at=expiration_time)
        db.session.add(reset_entry)
        db.session.commit()

        # Send the code to the user's email
        msg = Message('Password Reset Code', sender='impacttertiaryeducationalservi@gmail.com', recipients=[email])
        msg.body = f'Your password reset code is: {code}'
        mail.send(msg)

        flash('A password reset code has been sent to your email address.', 'success')
        return redirect(url_for('verify_code'))
    
    # For GET requests or if email is not provided, render the forgot_password.html template
    return render_template('forgot_password.html')

@app.route('/verify_code', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        code = request.form.get('code')
        email = request.form.get('email')

        # Find the code in the database
        reset_entry = PasswordReset.query.filter_by(email=email, code=code).first()

        if reset_entry and reset_entry.expires_at > datetime.utcnow():
            flash('Code verified successfully! You can now reset your password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid or expired code. Please request a new one.', 'danger')
            return redirect(url_for('verify_code'))

    return render_template('verify_code.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password'))

        email = request.form.get('email')

        # Find the user and update the password
        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()

            # Optionally, delete the reset code from the database
            PasswordReset.query.filter_by(email=email).delete()
            db.session.commit()

            flash('Password has been updated successfully.', 'success')
            return redirect(url_for('login'))

        flash('User not found.', 'danger')
        return redirect(url_for('reset_password'))

    return render_template('verify_code.html')

@app.route('/friends/<int:user_id>', methods=['POST'])
def send_friend_request(user_id):
    if 'user_id' not in session:
        flash('You must be logged in to send a friend request.', 'danger')
        return redirect(url_for('login'))
    
    from_user = User.query.get(session['user_id'])
    to_user = User.query.get(user_id)
    
    # Check if a friend request already exists
    existing_request = FriendRequest.query.filter_by(from_user_id=from_user.id, to_user_id=to_user.id).first()
    
    if existing_request:
        flash('Friend request already sent.', 'danger')
    else:
        friend_request = FriendRequest(from_user_id=from_user.id, to_user_id=to_user.id)
        db.session.add(friend_request)
        db.session.commit()
        flash(f'Friend request sent to {to_user.firstname} {to_user.lastname}!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    
    if friend_request.to_user_id != session['user_id']:
        flash('You do not have permission to accept this request.', 'danger')
        return redirect(url_for('dashboard'))
    
    friend_request.status = 'accepted'
    db.session.commit()
    flash('Friend request accepted!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
def reject_friend_request(request_id):
    friend_request = FriendRequest.query.get_or_404(request_id)
    
    if friend_request.to_user_id != session['user_id']:
        flash('You do not have permission to reject this request.', 'danger')
        return redirect(url_for('dashboard'))
    
    friend_request.status = 'rejected'
    db.session.commit()
    flash('Friend request rejected.', 'danger')
    
    return redirect(url_for('dashboard'))


@app.route('/handle_friend_request/<int:request_id>/<string:action>', methods=['POST'])
def handle_friend_request(request_id, action):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    friend_request = FriendRequest.query.get_or_404(request_id)

    # Ensure the logged-in user is the recipient of the friend request
    if friend_request.to_user_id != session['user_id']:
        flash('You are not authorized to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    if action == 'accept':
        friend_request.status = 'accepted'
        flash('Friend request accepted.', 'success')
    elif action == 'reject':
        friend_request.status = 'rejected'
        flash('Friend request rejected.', 'info')

    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure all tables are created
    app.run(debug=True)
