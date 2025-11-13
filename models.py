from datetime import datetime
from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    orders = db.relationship("Order", backref="user", lazy=True)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    carrier = db.Column(db.String(64), nullable=False)
    service = db.Column(db.String(64), nullable=False)
    weight_oz = db.Column(db.Float, nullable=False)
    from_address = db.Column(db.Text, nullable=False)
    to_address = db.Column(db.Text, nullable=False)
    reference = db.Column(db.String(255))

    amount_usd = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(32), default="pending_payment", index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    payments = db.relationship("Payment", backref="order", lazy=True)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)

    provider = db.Column(db.String(64), nullable=False)
    provider_payment_id = db.Column(db.String(128), nullable=False, index=True)
    amount_usd = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(32), default="crypto")
    status = db.Column(db.String(32), default="pending")

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
