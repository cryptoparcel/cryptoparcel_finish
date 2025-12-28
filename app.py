from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    jsonify,
    current_app,
)
from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user,
)
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from datetime import datetime, timedelta
import logging
import os
import hmac
import hashlib
import requests
import smtplib
import json
import secrets
from email.message import EmailMessage
from config import Config
from label_generator import generate_shipping_label_pdf
from extensions import db, login_manager, limiter, migrate

load_dotenv()

def calculate_label_price(carrier: str, service: str, weight_oz: float) -> float:
    """Simple placeholder rate logic (replace later with real carrier APIs)."""
    base_price = 3.00
    per_oz = 0.10
    fast_keywords = ["express", "overnight", "priority", "next day", "2day", "2-day"]
    if any(k in service.lower() for k in fast_keywords):
        base_price += 2.00
    return round(base_price + weight_oz * per_oz, 2)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Core extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)

    # Logging
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        csp = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
        )
        response.headers.setdefault("Content-Security-Policy", csp)
        return response

    with app.app_context():
        from models import User, Order, Payment, WalletLog
        db.create_all()

    register_routes(app)
    return app

@login_manager.user_loader
def load_user(user_id):
    from models import User
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

def is_admin() -> bool:
    """Only the first registered user (ID 1) has admin access."""
    return current_user.is_authenticated and current_user.id == 1

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash("Admin access required.", "error")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)
    return wrapper

def send_email(subject: str, to_email: str, html_body: str, text_body: str | None = None):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM")
    if not all([host, user, password, from_email]):
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(text_body or "You have a new notification from CryptoParcel.")
    msg.add_alternative(html_body, subtype="html")
    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to send email: {e}")

def log_wallet_change(user, amount_change: float, reason: str):
    from models import WalletLog
    wl = WalletLog(
        user_id=user.id,
        amount_change=amount_change,
        reason=reason,
        created_at=datetime.utcnow(),
    )
    db.session.add(wl)

def verify_nowpayments_signature(raw_body: bytes, signature: str) -> bool:
    secret = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
    if not secret or not signature:
        return False
    try:
        body_str = (raw_body or b"").decode("utf-8")
        data = json.loads(body_str or "{}")
        ordered = json.dumps(data, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(secret.encode("utf-8"), ordered.encode("utf-8"), hashlib.sha512).hexdigest()
    except Exception:
        return False
    return hmac.compare_digest(expected, signature)

def get_nowpayments_payment(payment_id: str) -> dict:
    api_key = os.getenv("NOWPAYMENTS_API_KEY")
    base_url = os.getenv("NOWPAYMENTS_BASE_URL", "https://api.nowpayments.io")
    url = f"{base_url.rstrip('/')}/v1/payment/{payment_id}"
    headers = {"x-api-key": api_key} if api_key else {}
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()

def create_nowpayments_invoice(order) -> dict:
    api_key = os.getenv("NOWPAYMENTS_API_KEY")
    base_url = os.getenv("NOWPAYMENTS_BASE_URL", "https://api.nowpayments.io")
    url = f"{base_url.rstrip('/')}/v1/invoice"
    payload = {
        "price_amount": order.amount_usd,
        "price_currency": "usd",
        "order_id": str(order.id),
        "ipn_callback_url": url_for("nowpayments_ipn", _external=True),
        "success_url": url_for("order_detail", order_id=order.id, _external=True),
        "cancel_url": url_for("orders", _external=True),
    }
    headers = {"x-api-key": api_key} if api_key else {}
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()

def create_topup_invoice(payment) -> dict:
    api_key = os.getenv("NOWPAYMENTS_API_KEY")
    base_url = os.getenv("NOWPAYMENTS_BASE_URL", "https://api.nowpayments.io")
    url = f"{base_url.rstrip('/')}/v1/invoice"
    payload = {
        "price_amount": payment.amount_usd,
        "price_currency": "usd",
        "order_id": f"topup-{payment.id}",
        "ipn_callback_url": url_for("nowpayments_ipn", _external=True),
        "success_url": url_for("wallet", _external=True),
        "cancel_url": url_for("wallet", _external=True),
    }
    headers = {"x-api-key": api_key} if api_key else {}
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()

def run_auto_cleanup():
    from models import Order, Payment
    now = datetime.utcnow()
    cutoff_orders = now - timedelta(minutes=15)
    stale_orders = Order.query.filter(
        Order.status.in_(["pending_payment", "payment_error"]),
        Order.created_at < cutoff_orders,
    ).all()
    for o in stale_orders:
        o.status = "cancelled_auto"
    cutoff_payments = now - timedelta(minutes=60)
    stale_payments = Payment.query.filter(
        Payment.status == "waiting",
        Payment.created_at < cutoff_payments,
    ).all()
    for p in stale_payments:
        p.status = "expired"
    if stale_orders or stale_payments:
        db.session.commit()

def register_routes(app: Flask):
    from models import User, Order, Payment, WalletLog

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("create_label"))
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            if not email or not password:
                flash("Email and password required.", "error")
                return redirect(url_for("register"))
            if len(password) < 8:
                flash("Password must be 8+ characters.", "error")
                return redirect(url_for("register"))
            if password != confirm:
                flash("Passwords do not match.", "error")
                return redirect(url_for("register"))
            if User.query.filter_by(email=email).first():
                flash("Email already registered.", "error")
                return redirect(url_for("register"))
            user = User(email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            flash("Account created. Log in to continue.", "success")
            return redirect(url_for("login"))
        return render_template("auth/register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid email or password.", "error")
                return redirect(url_for("login"))
            login_user(user)
            return redirect(url_for("create_label"))
        return render_template("auth/login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out.", "info")
        return redirect(url_for("index"))

    @app.route("/orders")
    @login_required
    def orders():
        run_auto_cleanup()
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
        total_spent = db.session.query(func.coalesce(func.sum(Order.amount_usd), 0.0)) \
            .filter(Order.user_id == current_user.id, Order.status.in_(["paid", "confirmed", "finished"])) \
            .scalar() or 0.0
        return render_template("orders.html", orders=orders, total_spent=total_spent)

    @app.route("/orders/<int:order_id>")
    @login_required
    def order_detail(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id and not is_admin():
            flash("Unauthorized", "error")
            return redirect(url_for("orders"))
        return render_template("order_detail.html", order=order)

    @app.route("/wallet")
    @login_required
    def wallet():
        from models import Payment, WalletLog
        np_id = request.args.get("NP_id") or request.args.get("np_id")
        if np_id:
            try:
                data = get_nowpayments_payment(np_id)
                payment_status = (data.get("payment_status") or "").lower()
                order_id = data.get("order_id") or ""
                if order_id.startswith("topup-"):
                    raw_id = order_id.split("topup-", 1)[1]
                    if raw_id.isdigit():
                        payment = Payment.query.get(int(raw_id))
                        if payment and payment.type == "topup" and payment.status != "paid" and payment_status in {"finished", "confirmed", "paid"}:
                            user = User.query.get(payment.user_id)
                            if user:
                                user.balance_usd = (user.balance_usd or 0.0) + payment.amount_usd
                                log_wallet_change(user, payment.amount_usd, "Wallet top-up via NOWPayments")
                            payment.status = "paid"
                            db.session.commit()
            except Exception as e:
                current_app.logger.warning(f"NOWPayments return error: {e}")

        topups = Payment.query.filter_by(user_id=current_user.id, type="topup").order_by(Payment.created_at.desc()).limit(20).all()
        logs = WalletLog.query.filter_by(user_id=current_user.id).order_by(WalletLog.created_at.desc()).limit(20).all()
        balance = current_user.balance_usd or 0.0
        return render_template("wallet.html", balance=balance, topups=topups, logs=logs)

    @app.route("/wallet/topup", methods=["GET", "POST"])
    @login_required
    def wallet_topup():
        from models import Payment
        if request.method == "POST":
            try:
                amount = float(request.form.get("amount_usd", "0"))
            except ValueError:
                flash("Invalid amount.", "error")
                return redirect(url_for("wallet_topup"))
            if not (1 <= amount <= 5000):
                flash("Amount must be $1–$5000.", "error")
                return redirect(url_for("wallet_topup"))
            payment = Payment(user_id=current_user.id, type="topup", amount_usd=amount, currency="crypto", status="waiting", provider="nowpayments")
            db.session.add(payment)
            db.session.commit()
            try:
                invoice = create_topup_invoice(payment)
                payment.provider_payment_id = str(invoice.get("payment_id") or invoice.get("id") or "")
                db.session.commit()
                return redirect(invoice.get("invoice_url"))
            except Exception as e:
                current_app.logger.error(f"Topup invoice error: {e}")
                payment.status = "payment_error"
                db.session.commit()
                flash("Payment failed. Try again.", "error")
                return redirect(url_for("wallet"))
        return render_template("wallet_topup.html", balance=current_user.balance_usd or 0.0)

    @app.route("/create-label", methods=["GET", "POST"])
    @login_required
    def create_label():
        from models import Order, Payment, User
        if request.method == "POST":
            payment_method = (request.form.get("payment_method") or "auto").lower()
            service = request.form.get("service") or "USPS First-Class"
            carrier_raw = (request.form.get("carrier") or "").strip().upper()
            carrier = "USPS" if service.startswith("USPS") else "UPS" if service.startswith("UPS") else "FedEx" if service.startswith("FedEx") else carrier_raw or "Custom"
            weight_lb_str = request.form.get("weight_lb") or ""
            weight_oz_str = request.form.get("weight_oz") or ""
            try:
                weight_oz = float(weight_oz_str) if weight_oz_str else float(weight_lb_str) * 16.0 if weight_lb_str else 0.0
            except ValueError:
                flash("Invalid weight.", "error")
                return redirect(url_for("create_label"))
            if weight_oz <= 0 or weight_oz > 10000:
                flash("Weight must be between 0 and 10,000 oz.", "error")
                return redirect(url_for("create_label"))

            from_name = request.form.get("from_name", "").strip()
            from_address = request.form.get("from_address", "").strip()
            from_city = request.form.get("from_city", "").strip()
            from_state = request.form.get("from_state", "").strip()
            from_zip = request.form.get("from_zip", "").strip()
            to_name = request.form.get("to_name", "").strip()
            to_address = request.form.get("to_address", "").strip()
            to_city = request.form.get("to_city", "").strip()
            to_state = request.form.get("to_state", "").strip()
            to_zip = request.form.get("to_zip", "").strip()

            if not all([from_name, from_address, from_city, from_state, from_zip]):
                flash("From address incomplete.", "error")
                return redirect(url_for("create_label"))
            if not all([to_name, to_address, to_city, to_state, to_zip]):
                flash("To address incomplete.", "error")
                return redirect(url_for("create_label"))

            from_full = f"{from_name}\n{from_address}\n{from_city}, {from_state} {from_zip}\nUnited States"
            to_full = f"{to_name}\n{to_address}\n{to_city}, {to_state} {to_zip}\nUnited States"
            reference = request.form.get("reference", "").strip()

            amount_usd = calculate_label_price(carrier, service, weight_oz)

            order = Order(
                user_id=current_user.id,
                carrier=carrier,
                service=service,
                weight_oz=weight_oz,
                from_address=from_full,
                to_address=to_full,
                reference=reference,
                amount_usd=amount_usd,
                status="pending_payment",
            )
            db.session.add(order)
            db.session.commit()

            user_balance = current_user.balance_usd or 0.0

            if payment_method == "wallet" or user_balance >= amount_usd:
                if user_balance < amount_usd:
                    flash("Insufficient balance. Top up or use crypto.", "error")
                    return redirect(url_for("create_label"))
                current_user.balance_usd = user_balance - amount_usd
                order.status = "paid"
                payment = Payment(
                    order_id=order.id,
                    user_id=current_user.id,
                    type="label",
                    provider="wallet",
                    amount_usd=amount_usd,
                    currency="usd",
                    status="paid",
                )
                db.session.add(payment)
                log_wallet_change(current_user, -amount_usd, f"Label #{order.id}")
                db.session.commit()
                flash("Label paid with wallet!", "success")
                return redirect(url_for("order_detail", order_id=order.id))

            try:
                invoice = create_nowpayments_invoice(order)
                payment = Payment(
                    order_id=order.id,
                    user_id=current_user.id,
                    type="label",
                    provider="nowpayments",
                    provider_payment_id=str(invoice.get("payment_id") or ""),
                    amount_usd=amount_usd,
                    currency="crypto",
                    status="waiting",
                )
                db.session.add(payment)
                db.session.commit()
                return redirect(invoice.get("invoice_url"))
            except Exception as e:
                current_app.logger.error(f"NOWPayments error: {e}")
                order.status = "payment_error"
                db.session.commit()
                flash("Crypto payment failed. Try again.", "error")
                return redirect(url_for("order_detail", order_id=order.id))

        return render_template("create_label.html", balance=current_user.balance_usd or 0.0)

    @app.route("/nowpayments/ipn", methods=["POST"])
    @limiter.limit("30 per minute")
    def nowpayments_ipn():
        raw_body = request.data or b""
        signature = request.headers.get("x-nowpayments-sig", "")
        if not verify_nowpayments_signature(raw_body, signature):
            return "invalid signature", 400
        try:
            data = request.get_json(force=True)
        except Exception:
            return "invalid json", 400
        payment_id = str(data.get("payment_id") or "")
        payment_status = (data.get("payment_status") or "").lower()
        if not payment_id:
            return "missing payment_id", 400
        payment = Payment.query.filter_by(provider_payment_id=payment_id).first()
        if not payment:
            return "payment not found", 404
        if payment_status in {"finished", "confirmed", "paid"} and payment.status != "paid":
            payment.status = "paid"
            if payment.type == "topup":
                user = User.query.get(payment.user_id)
                if user:
                    user.balance_usd = (user.balance_usd or 0.0) + payment.amount_usd
                    log_wallet_change(user, payment.amount_usd, "Wallet top-up")
                db.session.commit()
            elif payment.type == "label":
                order = Order.query.get(payment.order_id)
                if order:
                    order.status = "paid"
                    db.session.commit()
        return "ok", 200

    @app.route("/support", methods=["GET", "POST"])
    def support():
        if request.method == "POST":
            email = request.form.get("email") or (current_user.email if current_user.is_authenticated else "")
            order_id = request.form.get("order_id") or ""
            reason = request.form.get("reason") or ""
            message = request.form.get("message") or ""
            current_app.logger.info(f"Support request: {email} | Order {order_id} | {reason} | {message}")
            flash("Message sent! We'll reply soon.", "success")
            return redirect(url_for("support"))
        return render_template("support.html")

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        current_app.logger.error(f"Server error: {e}")
        return render_template("errors/500.html"), 500

app = create_app()

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    from models import User
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not check_password_hash(current_user.password_hash, current):
                flash("Current password wrong.", "error")
                return redirect(url_for("settings"))
            if len(new) < 8:
                flash("New password too short.", "error")
                return redirect(url_for("settings"))
            if new != confirm:
                flash("Passwords don't match.", "error")
                return redirect(url_for("settings"))
            current_user.password_hash = generate_password_hash(new)
            db.session.commit()
            flash("Password updated.", "success")
        elif action == "delete_account":
            if request.form.get("confirm", "").lower() != "delete":
                flash("Type DELETE to confirm.", "error")
                return redirect(url_for("settings"))
            logout_user()
            Payment.query.filter_by(user_id=current_user.id).delete()
            Order.query.filter_by(user_id=current_user.id).delete()
            WalletLog.query.filter_by(user_id=current_user.id).delete()
            db.session.delete(current_user)
            db.session.commit()
            flash("Account deleted.", "info")
            return redirect(url_for("index"))
    return render_template("settings.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)), debug=True)
