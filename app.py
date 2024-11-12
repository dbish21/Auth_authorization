from flask import Flask, render_template, redirect, session, flash, url_for, abort
from flask_mail import Mail, Message
from functools import wraps
from models import db, connect_db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm, PasswordResetRequestForm, PasswordResetForm
import os
import secrets

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5433/feedback_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'shhhh')

# Mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

mail = Mail(app)
connect_db(app)

# Decorator functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in first", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please log in first", "danger")
            return redirect(url_for('login'))
        user = User.query.filter_by(username=session['username']).first()
        if not user.is_admin:
            abort(401)
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('user_page', username=session['username']))

    form = RegisterForm()
    if form.validate_on_submit():
        try:
            user = User.register(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data
            )
            db.session.add(user)
            db.session.commit()
            session['username'] = user.username
            flash('Registration successful!', 'success')
            return redirect(url_for('user_page', username=user.username))
        except IntegrityError:
            db.session.rollback()
            flash('Username/email already taken', 'danger')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('user_page', username=session['username']))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.authenticate(form.username.data, form.password.data)
        if user:
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('user_page', username=user.username))
        flash('Invalid username/password', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Goodbye!', 'info')
    return redirect(url_for('login'))

@app.route('/users/<username>')
@login_required
def user_page(username):
    user = User.query.get_or_404(username)
    if username != session['username'] and not User.query.filter_by(username=session['username']).first().is_admin:
        abort(401)
    return render_template('user.html', user=user)

@app.route('/users/<username>/delete', methods=['POST'])
@login_required
def delete_user(username):
    user = User.query.get_or_404(username)
    if username != session['username'] and not User.query.filter_by(username=session['username']).first().is_admin:
        abort(401)
    db.session.delete(user)
    db.session.commit()
    session.pop('username', None)
    flash('User deleted', 'info')
    return redirect(url_for('register'))

# Feedback routes
@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
@login_required
def add_feedback(username):
    if username != session['username'] and not User.query.filter_by(username=session['username']).first().is_admin:
        abort(401)
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback = Feedback(
            title=form.title.data,
            content=form.content.data,
            username=username,
        )
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback added!', 'success')
        return redirect(url_for('user_page', username=username))

    return render_template('feedback/add.html', form=form)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
@login_required
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if feedback.username != session['username'] and not User.query.filter_by(username=session['username']).first().is_admin:
        abort(401)
    
    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback updated!', 'success')
        return redirect(url_for('user_page', username=feedback.username))

    return render_template('feedback/edit.html', form=form, feedback=feedback)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if feedback.username != session['username'] and not User.query.filter_by(username=session['username']).first().is_admin:
        abort(401)
    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback deleted', 'info')
    return redirect(url_for('user_page', username=feedback.username))

# Password reset routes
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if 'username' in session:
        return redirect(url_for('user_page', username=session['username']))
        
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            db.session.commit()
            
            msg = Message('Password Reset Request',
                          sender='noreply@yourdomain.com',
                          recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
            mail.send(msg)
            flash('Check your email for the instructions to reset your password', 'info')
            return redirect(url_for('login'))
        flash('Email address not found', 'danger')
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'username' in session:
        return redirect(url_for('user_page', username=session['username']))
        
    user = User.query.filter_by(reset_token=token).first()
    if user is None:
        flash('That is an invalid or expired reset token', 'warning')
        return redirect(url_for('reset_password_request'))
    
    form = PasswordResetForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        user.reset_token = None
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(401)
def unauthorized(e):
    return render_template('errors/401.html'), 401

if __name__ == '__main__':
    app.run(debug=True)