from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

# Single SQLAlchemy instance used app-wide
db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    balance_usd = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    orders = db.relationship("Order", backref="user", lazy=True)
    payments = db.relationship("Payment", backref="user", lazy=True)


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

    status = db.Column(db.String(32), default="pending_payment", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    payments = db.relationship("Payment", backref="order", lazy=True)


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Optional link to an order (for label purchases)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=True)

    # Link to the user (for both label purchases and balance top-ups)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # "label" for label purchases, "topup" for balance funding
    type = db.Column(db.String(20), nullable=False, default="label")

    provider = db.Column(db.String(64), nullable=False, default="nowpayments")
    provider_payment_id = db.Column(db.String(128), nullable=True, index=True)
    amount_usd = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(32), default="crypto")
    status = db.Column(db.String(32), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
