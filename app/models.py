from app import db
from flask_login import UserMixin
from datetime import datetime

# Followers association table for many-to-many relationship
followers = db.Table(
    'follower',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    img = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    bio = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=False)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    sent_messages = db.relationship('UserMessage', foreign_keys='UserMessage.sender_id', backref='author', lazy=True)
    received_messages = db.relationship('UserMessage', foreign_keys='UserMessage.receiver_id', backref='receiver', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic'
    )

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        return Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
                followers.c.follower_id == self.id).order_by(
                    Post.timestamp.desc()
                )
    
    def get_unique_followers_and_following(self):
        followers = set(self.followers.all())
        following = set(self.followed.all())
        return list(followers.union(following))

    def __repr__(self):
        return f'<User {self.username} {self.email}>'
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.String(1024), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return f'<Post {self.title} by User ID {self.user_id}>'

class UserMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<UserMessage from {self.sender_id} to {self.receiver_id}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Notification for User ID {self.user_id}>'
