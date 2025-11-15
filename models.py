from datetime import datetime
from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    balance_usd = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    orders = db.relationship("Order", backref="user", lazy=True)
    payments = db.relationship("Payment", backref="user", lazy=True)
    wallet_logs = db.relationship("WalletLog", backref="user", lazy=True)
    api_keys = db.relationship("APIKey", backref="user", lazy=True)
    address_profiles = db.relationship("AddressProfile", backref="user", lazy=True)
    team_memberships = db.relationship("TeamMembership", backref="user", lazy=True)


class Order(db.Model):
    __tablename__ = "order"

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

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    payments = db.relationship("Payment", backref="order", lazy=True)


class Payment(db.Model):
    __tablename__ = "payment"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    # "label" for label purchase, "topup" for wallet top-ups
    type = db.Column(db.String(20), nullable=False, default="label")

    provider = db.Column(db.String(64), nullable=True)  # wallet, nowpayments, etc.
    provider_payment_id = db.Column(db.String(128), nullable=True, index=True)

    amount_usd = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(32), default="usd")
    status = db.Column(db.String(32), default="pending")

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class WalletLog(db.Model):
    __tablename__ = "wallet_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount_change = db.Column(db.Float, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class APIKey(db.Model):
    # Renamed again to avoid leftover Postgres sequence conflicts
    __tablename__ = "cp_user_api_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    key = db.Column(db.String(128), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)


class AddressProfile(db.Model):
    __tablename__ = "address_profile"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False)  # "from" or "to"
    label = db.Column(db.String(120), nullable=False)

    name = db.Column(db.String(255))
    street1 = db.Column(db.String(255), nullable=False)
    street2 = db.Column(db.String(255))
    city = db.Column(db.String(255), nullable=False)
    state = db.Column(db.String(64), nullable=False)
    zip = db.Column(db.String(32), nullable=False)
    country = db.Column(db.String(64), nullable=False, default="United States")

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class TeamMembership(db.Model):
    __tablename__ = "team_membership"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    role = db.Column(db.String(32), nullable=False, default="owner")  # "owner", "staff"
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
