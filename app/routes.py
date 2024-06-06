from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_mail import Message
from .forms import RegistrationForm, LoginForm, AddPost, ResetPasswordRequestForm, ResetPassword, ResetConfirmationLink, UpdateProfileForm, EditPostForm, MessageForm
from app import app, db, login_manager, mail, bcrypt
from app.models import Post, User, UserMessage, Notification
from app.utils import generate_confirmation_token, confirm_token
from flask_login import current_user, logout_user, login_user, login_required
from itsdangerous import SignatureExpired, BadTimeSignature, URLSafeTimedSerializer
import os
import secrets


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_required
@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    if current_user.is_anonymous:
        return redirect(url_for('landingpage'))
    form = AddPost()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data,
                    user_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))

    # Pagination
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(page=page, per_page=10)
    
    return render_template('home.html', title='Home', posts=posts, form=form)


@app.route('/about/<username>', methods=['GET', 'POST'])
@login_required
def about(username):
    user = User.query.filter_by(username=username).first_or_404()
    form = UpdateProfileForm()
    if form.validate_on_submit() and current_user == user:
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.img = picture_file
        current_user.username = form.username.data
        current_user.bio = form.bio.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('about', username=current_user.username))
    elif request.method == 'GET':
        form.username.data = user.username
        form.bio.data = user.bio
    
    page = request.args.get('page', 1, type=int)
    posts = user.posts.order_by(Post.timestamp.desc()).paginate(page=page, per_page=10)
    
    return render_template('about.html', title=f"{user.username}'s Profile", user=user, form=form, posts=posts)
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)
    form_picture.save(picture_path)
    return picture_fn

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        unread_count = UserMessage.query.filter_by(receiver_id=current_user.id, read=False).count()
        return dict(unread_count=unread_count)
    return dict(unread_count=0)


@app.route('/contact')
def contact():
    return render_template('contact.html', title='Contact')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data,
                    password=password_hash)
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(user.email, subject, html)
        flash('A confirmation email has been sent via email.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_USERNAME']
    )
    mail.send(msg)

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
        if not email or not isinstance(email, str):
            raise ValueError("Invalid email")
    except SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
        return redirect(url_for('resend_confirmation'))
    except BadTimeSignature:
        flash('The confirmation link is invalid.', 'danger')
        return redirect(url_for('resend_confirmation'))
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.is_active:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.is_active = True
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

@app.route('/resend_confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = ResetConfirmationLink()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user is None:
            flash('Email address not found.', 'danger')
            return redirect(url_for('resend_confirmation'))
        
        if user.is_active:
            flash('Account already confirmed. Please login.', 'success')
            return redirect(url_for('login'))
        
    # generate new confirmation token
        token = generate_confirmation_token(user.email)
        confrim_url = url_for('confirm_email', token=token, _external=True)
        subject = 'Please confrim your email'
        html = render_template('confirm.html', confrim_url=confrim_url)

        #send confirmation email
        send_email(user.email, subject, html)
        flash('A new confirmation email has been sent.', 'success')
        return  redirect(url_for('login'))
    
    return render_template('resend_confirmation.html', title='Resend Confirmation', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.is_active:
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Please activate your account first.', 'warning')
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@login_required
@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/follow/<username>')
def follow(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User {} not found'.format(username), 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot follow yourself!', 'danger')
        return redirect(url_for('about', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('You are now following {}'.format(username), 'success')
    return redirect(url_for('about', username=username))


@app.route('/unfollow/<username>')
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User {} not found'.format(username), 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot unfollow yourself!', 'danger')
        return redirect(url_for('about', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You have unfollowed {}'.format(username), 'success')
    return redirect(url_for('about', username=username))

@app.route('/landingpage')
def landingpage():
    return render_template('landingpage.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_confirmation_token(user.email)
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = "Password Reset Requested"
            html = render_template('reset_password_email.html', reset_url=reset_url)
            send_email(user.email, subject, html)
            flash('A password reset email has been sent to you.', 'info')
        else:
            flash('Email address not found.', 'danger')     
            return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = confirm_token(token)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('reset_password_request'))
    form = ResetPassword()

    if form.validate_on_submit():
        password = form.password.data
        user = User.query.filter_by(email=email).first_or_404()
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = password_hash
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form)


@login_required
@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = EditPostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('edit_post.html', title='Edit Post', form=form, post=post)


@login_required
@app.route('/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

@app.route('/messages/<username>', methods=['GET', 'POST'])
@login_required
def conversation(username):
    user = User.query.filter_by(username=username).first_or_404()
    form = MessageForm()
    if form.validate_on_submit():
        message = UserMessage(content=form.content.data, sender_id=current_user.id, receiver_id=user.id)
        db.session.add(message)
        db.session.commit()
        # flash('Your message has been sent!', 'success')
        return redirect(url_for('conversation', username=username))
    
    messages_sent = UserMessage.query.filter_by(sender_id=current_user.id, receiver_id=user.id)
    messages_received = UserMessage.query.filter_by(sender_id=user.id, receiver_id=current_user.id)
    all_messages = messages_sent.union(messages_received).order_by(UserMessage.timestamp.asc())

    for message in messages_received:
        if not message.read:
            message.read = True
    db.session.commit()
    
    return render_template('conversation.html', title=f'Conversation with {username}', messages=all_messages, form=form, receiver=user)

@app.route('/message_list')
@login_required
def message_list():
    messages = UserMessage.query.filter_by(receiver_id=current_user.id).order_by(UserMessage.timestamp.desc()).all()
    unread_count = UserMessage.query.filter_by(receiver_id=current_user.id, read=False).count()
    return render_template('message_list.html', title='Messages', messages=messages, unread_count=unread_count)

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id, read=False).all()
    for notification in notifications:
        notification.read = True
    db.session.commit()
    return render_template('notifications.html', title='Notifications', notifications=notifications)

@app.route('/users/<username>')
@login_required
def users(username):
    user = User.query.filter_by(username=username).first_or_404()
    unique_users = user.get_unique_followers_and_following()
    return render_template('users.html', title='Users', users=unique_users)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401