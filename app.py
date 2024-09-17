from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email
from datetime import datetime



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'   # Necessary for using forms

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grapplepit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect users to the login page if unauthorized

# Admin user authorization
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # New field for role
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # New field for registration timestamp

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Added the User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Contact form definition
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email',[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

# Contact message model for the database
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)

# Applications routes
@app.route('/')
def home():
    return render_template('index.html')

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Classes route
@app.route('/classes')
def classes():
    return render_template('classes.html')

@app.route('/schedule')
def schedule():
    # Define a sample schedule
    schedule = {
        'Monday': ['6:00 AM - BJJ', '6:00 PM - BJJ'],
        'Tuesday': ['6:00 AM - No Gi', '6:00 PM - No Gi'],
        'Wednesday': ['6:00 AM - BJJ', '6:00 PM - Advanced BJJ'],
        'Thursday': ['6:00 AM - No Gi', '6:00 PM - BJJ'],
        'Friday': ['6:00 AM - BJJ', '6:00 PM - BJJ'],
        'Saturday': ['11:00 AM - Competition Class'],
        'Sunday': []
    }
    
    return render_template('schedule.html', schedule=schedule)



# Contact route
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        # Save form data to the database
        new_message = ContactMessage(
            name=form.name.data,
            email=form.email.data,
            message=form.message.data
        )
        db.session.add(new_message)
        db.session.commit()     # This line ensures the data is saved
        flash(f'Thank you for your message, {form.name.data}!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # New role field

        # Check if the user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password matches
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!')

            # Redirect based on user role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('profile'))  # Redirect regular users to profile

        else:
            flash('Invalid username or password!')

    return render_template('login.html')


# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('login'))

# Admin route
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('login'))

    messages = ContactMessage.query.all()
    return render_template('admin.html', messages=messages)

# Admin Dashboard route
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('login'))

    # User statistics
    total_users = User.query.count()
    total_admins = User.query.filter_by(role='admin').count()

    # User roles for the chart
    users_per_role = User.query.with_entities(User.role, db.func.count(User.role)).group_by(User.role).all()

    # User registrations by day (last 7 days)
    daily_registrations = db.session.query(
        db.func.date(User.created_at), db.func.count(User.id)
    ).group_by(db.func.date(User.created_at)).order_by(db.func.date(User.created_at)).limit(7).all()
    
    # Weekly registrations (group by week, last 4 weeks)
    weekly_registrations = db.session.query(
        db.func.strftime('%Y-%W', User.created_at), db.func.count(User.id)
    ).group_by(db.func.strftime('%Y-%W', User.created_at)).order_by(db.func.strftime('%Y-%W', User.created_at)).limit(4).all()

    # Monthly registrations (group by month, last 3 months)
    monthly_registrations = db.session.query(
        db.func.strftime('%Y-%m', User.created_at), db.func.count(User.id)
    ).group_by(db.func.strftime('%Y-%m', User.created_at)).order_by(db.func.strftime('%Y-%m', User.created_at)).limit(3).all()

    # List of recently registered users
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()

    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_admins=total_admins,
        users_per_role=users_per_role,
        daily_registrations=daily_registrations,
        weekly_registrations=weekly_registrations,
        monthly_registrations=monthly_registrations,
        recent_users=recent_users
    )

# User Management
@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('manage_users.html', users=users)

# User Delete Route - Admin Only
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('You are not authorized to delete users.', 'danger')
        return redirect(url_for('manage_users'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} has been deleted.', 'success')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('manage_users'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user  # Automatically get the current logged-in user

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = request.form.get('password')

        # Validate and update username
        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash('Username is already taken!', 'danger')
                return redirect(url_for('profile'))
            user.username = new_username
        
        # Update password
        if new_password:
            user.set_password(new_password)

        db.session.commit()
        flash('Your profile has been updated!', 'success')

    return render_template('profile.html', user=user)



if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create the database tables before starting the app
    app.run(debug=True)