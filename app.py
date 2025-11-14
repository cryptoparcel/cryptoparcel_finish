from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    send_file,
    jsonify,
    session,
    current_app,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import generate_password_hash, check_password_hash

from dotenv import load_dotenv
from datetime import datetime, timedelta
import logging
import os
import io
import hmac
import hashlib
import requests
import smtplib
import json
from email.message import EmailMessage

from config import Config
from label_generator import generate_shipping_label_pdf

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"

limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])


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

    # Core extensions
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

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
        # Import models so SQLAlchemy is aware of them
        from models import User, Order, Payment, WalletLog  # noqa: F401
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
    """Admin if logged in as user id 1 OR admin session flag set."""
    if getattr(current_user, "is_authenticated", False) and current_user.id == 1:
        return True
    return bool(session.get("admin_auth"))


def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash("Admin access required.", "error")
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


def send_email(subject: str, to_email: str, html_body: str, text_body: str | None = None):
    """Best-effort SMTP email sender using environment variables.

    Required env vars:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
    """
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM")

    if not host or not user or not password or not from_email:
        # Email not configured; silently skip
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    if not text_body:
        text_body = "You have a new notification from CryptoParcel."

    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
    except Exception as e:
        # Log but don't break app flow
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
    """Verify NOWPayments IPN signature using sorted JSON body.

    NOWPayments expects HMAC-SHA512 over JSON.stringify(params, Object.keys(params).sort())."""
    secret = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
    if not secret or not signature:
        return False
    try:
        body_str = (raw_body or b"").decode("utf-8")
        data = json.loads(body_str or "{}")
        ordered = json.dumps(data, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            secret.encode("utf-8"),
            ordered.encode("utf-8"),
            hashlib.sha512,
        ).hexdigest()
    except Exception:
        return False
    return hmac.compare_digest(expected, signature)


def get_nowpayments_payment(np_id: str) -> dict:
    """Fetch a single NOWPayments payment by its np_id (from redirect)."""
    api_key = os.getenv("NOWPAYMENTS_API_KEY")
    base_url = os.getenv("NOWPAYMENTS_BASE_URL", "https://api.nowpayments.io")
    # Use the np_id endpoint
    url = f"{base_url.rstrip('/')}/v1/payment/np_id/{np_id}"
    headers = {"x-api-key": api_key} if api_key else {}
    current_app.logger.info(f"Fetching NOWPayments payment status for np_id={np_id}")
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
    current_app.logger.info(f"Creating NOWPayments invoice for order {order.id}")
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
    current_app.logger.info(f"Creating NOWPayments topup invoice for payment {payment.id}")
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def run_auto_cleanup():
    """Auto-cancel / expire old objects for semi-autopilot behavior."""
    from models import Order, Payment

    now = datetime.utcnow()

    # Cancel orders stuck in pending or payment_error > 15 minutes
    cutoff_orders = now - timedelta(minutes=15)
    stale_orders = (
        Order.query.filter(
            Order.status.in_(["pending_payment", "payment_error"]),
            Order.created_at < cutoff_orders,
        ).all()
    )
    for o in stale_orders:
        o.status = "cancelled_auto"

    # Expire payments stuck waiting > 60 minutes
    cutoff_payments = now - timedelta(minutes=60)
    stale_payments = (
        Payment.query.filter(
            Payment.status == "waiting",
            Payment.created_at < cutoff_payments,
        ).all()
    )
    for p in stale_payments:
        p.status = "expired"

    if stale_orders or stale_payments:
        db.session.commit()


def register_routes(app: Flask):
    from models import User, Order, Payment, WalletLog

    # ----------------------- BASIC ROUTES -----------------------

    @app.route("/")
    def index():
        run_auto_cleanup()
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})

    # ----------------------- AUTH -----------------------

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def register():
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            confirm = request.form.get("confirm") or ""

            if not email or not password:
                flash("Email and password are required.", "error")
                return redirect(url_for("register"))

            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return redirect(url_for("register"))

            if password != confirm:
                flash("Passwords do not match.", "error")
                return redirect(url_for("register"))

            if User.query.filter_by(email=email).first():
                flash("Email is already registered.", "error")
                return redirect(url_for("register"))

            user = User(
                email=email,
                password_hash=generate_password_hash(password),
            )
            db.session.add(user)
            db.session.commit()

            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("auth/register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        if request.method == "POST":
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""

            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid email or password.", "error")
                return redirect(url_for("login"))

            login_user(user)
            return redirect(url_for("dashboard"))

        return render_template("auth/login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("You have been logged out.", "info")
        return redirect(url_for("index"))

    # ----------------------- DASHBOARD / ORDERS -----------------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        run_auto_cleanup()
        recent_orders = (
            Order.query.filter_by(user_id=current_user.id)
            .order_by(Order.created_at.desc())
            .limit(5)
            .all()
        )
        balance = current_user.balance_usd or 0.0
        return render_template(
            "dashboard.html",
            orders=recent_orders,
            balance=balance,
        )

    @app.route("/orders")
    @login_required
    def orders():
        orders = (
            Order.query.filter_by(user_id=current_user.id)
            .order_by(Order.created_at.desc())
            .all()
        )
        return render_template("orders.html", orders=orders)

    @app.route("/orders/<int:order_id>")
    @login_required
    def order_detail(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id and not is_admin():
            flash("Unauthorized", "error")
            return redirect(url_for("orders"))
        return render_template("order_detail.html", order=order)

    @app.route("/orders/<int:order_id>/label")
    @login_required
    def download_label(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id and not is_admin():
            flash("Unauthorized", "error")
            return redirect(url_for("orders"))

        if order.status != "paid":
            flash("This label is not yet paid.", "error")
            return redirect(url_for("order_detail", order_id=order.id))

        pdf_bytes = generate_shipping_label_pdf(order)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"label_{order.id}.pdf",
        )

    @app.route("/orders/<int:order_id>/cancel", methods=["POST"])
    @login_required
    def cancel_order(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id and not is_admin():
            flash("Unauthorized", "error")
            return redirect(url_for("orders"))

        if order.status not in ("pending_payment", "payment_error"):
            flash("This order cannot be cancelled.", "error")
            return redirect(url_for("order_detail", order_id=order.id))

        order.status = "cancelled"
        db.session.commit()
        flash("Order cancelled.", "info")
        return redirect(url_for("orders"))

    # ----------------------- WALLET -----------------------

    @app.route("/wallet")
    @login_required
    def wallet():
        # Check for NOWPayments redirect with NP_id and credit wallet if needed
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
                        success_statuses = {"finished", "confirmed", "paid", "completed"}
                        if (
                            payment
                            and payment.type == "topup"
                            and payment.status != "paid"
                            and payment_status in success_statuses
                        ):
                            user = User.query.get(payment.user_id)
                            if user:
                                user.balance_usd = (user.balance_usd or 0.0) + payment.amount_usd
                                log_wallet_change(
                                    user,
                                    payment.amount_usd,
                                    "Wallet top-up via NOWPayments (return)",
                                )
                            payment.status = "paid"
                            db.session.commit()
            except Exception as e:
                current_app.logger.warning(f"Error processing NOWPayments NP_id {np_id}: {e}")
        topups = (
            Payment.query.filter_by(user_id=current_user.id, type="topup")
            .order_by(Payment.created_at.desc())
            .limit(20)
            .all()
        )
        balance = current_user.balance_usd or 0.0
        logs = (
            WalletLog.query.filter_by(user_id=current_user.id)
            .order_by(WalletLog.created_at.desc())
            .limit(20)
            .all()
        )
        return render_template(
            "wallet.html",
            balance=balance,
            topups=topups,
            logs=logs,
        )

    @app.route("/wallet/topup", methods=["GET", "POST"])
    @login_required
    def wallet_topup():
        if request.method == "POST":
            amount_str = request.form.get("amount_usd") or "0"
            try:
                amount = float(amount_str)
            except ValueError:
                flash("Invalid amount.", "error")
                return redirect(url_for("wallet_topup"))

            if amount <= 0 or amount > 5000:
                flash("Amount must be between 1 and 5000 USD.", "error")
                return redirect(url_for("wallet_topup"))

            payment = Payment(
                user_id=current_user.id,
                type="topup",
                amount_usd=amount,
                currency="crypto",
                status="waiting",
                provider="nowpayments",
            )
            db.session.add(payment)
            db.session.commit()

            try:
                invoice = create_topup_invoice(payment)
            except Exception as e:
                current_app.logger.error(f"Error creating NOWPayments topup invoice: {e}")
                payment.status = "payment_error"
                db.session.commit()
                flash("Could not create crypto invoice, please try again later.", "error")
                return redirect(url_for("wallet"))

            payment.provider_payment_id = str(
                invoice.get("payment_id") or invoice.get("id") or ""
            )
            db.session.commit()

            return redirect(invoice.get("invoice_url"))

        return render_template("wallet_topup.html", balance=current_user.balance_usd or 0.0)

    # ----------------------- CREATE LABEL (wallet-first) -----------------------

    @app.route("/create-label", methods=["GET", "POST"])
    @login_required
    def create_label():
        if request.method == "POST":
            service = request.form.get("service") or "USPS First-Class"

            if service.startswith("USPS"):
                carrier = "USPS"
            elif service.startswith("UPS"):
                carrier = "UPS"
            elif service.startswith("FedEx"):
                carrier = "FedEx"
            else:
                carrier = "Custom"

            weight_str = request.form.get("weight_oz") or "0"
            try:
                weight_oz = float(weight_str)
            except ValueError:
                flash("Invalid weight.", "error")
                return redirect(url_for("create_label"))

            if weight_oz <= 0 or weight_oz > 10000:
                flash("Weight must be between 0 and 10000 oz.", "error")
                return redirect(url_for("create_label"))

            # From address
            fa_name = (request.form.get("from_name") or "").strip()
            fa_street1 = (request.form.get("from_street1") or "").strip()
            fa_city = (request.form.get("from_city") or "").strip()
            fa_state = (request.form.get("from_state") or "").strip()
            fa_zip = (request.form.get("from_zip") or "").strip()

            # To address
            ta_name = (request.form.get("to_name") or "").strip()
            ta_street1 = (request.form.get("to_street1") or "").strip()
            ta_city = (request.form.get("to_city") or "").strip()
            ta_state = (request.form.get("to_state") or "").strip()
            ta_zip = (request.form.get("to_zip") or "").strip()

            if not all([fa_name, fa_street1, fa_city, fa_state, fa_zip]):
                flash("From address is incomplete.", "error")
                return redirect(url_for("create_label"))
            if not all([ta_name, ta_street1, ta_city, ta_state, ta_zip]):
                flash("To address is incomplete.", "error")
                return redirect(url_for("create_label"))

            from_address = f"{fa_name}\n{fa_street1}\n{fa_city}, {fa_state} {fa_zip}\nUnited States"
            to_address = f"{ta_name}\n{ta_street1}\n{ta_city}, {ta_state} {ta_zip}\nUnited States"

            reference = (request.form.get("reference") or "").strip()
            amount_usd = calculate_label_price(carrier, service, weight_oz)

            order = Order(
                user_id=current_user.id,
                carrier=carrier,
                service=service,
                weight_oz=weight_oz,
                from_address=from_address,
                to_address=to_address,
                reference=reference,
                amount_usd=amount_usd,
                status="pending_payment",
            )
            db.session.add(order)
            db.session.commit()

            # WALLET-FIRST LOGIC
            user_balance = current_user.balance_usd or 0.0
            if user_balance >= amount_usd:
                current_user.balance_usd = user_balance - amount_usd
                order.status = "paid"

                wallet_payment = Payment(
                    order_id=order.id,
                    user_id=current_user.id,
                    type="label",
                    provider="wallet",
                    provider_payment_id=None,
                    amount_usd=amount_usd,
                    currency="usd",
                    status="paid",
                )
                db.session.add(wallet_payment)
                log_wallet_change(current_user, -amount_usd, f"Label #{order.id} purchase")
                db.session.commit()

                # Email notification
                try:
                    send_email(
                        subject="Your CryptoParcel label is paid",
                        to_email=current_user.email,
                        html_body=f"<p>Your label #{order.id} has been paid using your wallet balance.</p>",
                        text_body=f"Your label #{order.id} has been paid using your wallet balance.",
                    )
                except Exception:
                    pass

                flash("Label paid using your wallet balance.", "success")
                return redirect(url_for("order_detail", order_id=order.id))

            # Crypto fallback via NOWPayments
            try:
                invoice = create_nowpayments_invoice(order)
            except Exception as e:
                current_app.logger.error(f"Error creating NOWPayments invoice: {e}")
                order.status = "payment_error"
                db.session.commit()
                flash(
                    "We could not create a crypto invoice. Please try again later.",
                    "error",
                )
                return redirect(url_for("order_detail", order_id=order.id))

            payment = Payment(
                order_id=order.id,
                user_id=current_user.id,
                type="label",
                provider="nowpayments",
                provider_payment_id=str(
                    invoice.get("payment_id") or invoice.get("id") or ""
                ),
                amount_usd=amount_usd,
                currency="crypto",
                status="waiting",
            )
            db.session.add(payment)
            db.session.commit()

            return redirect(invoice.get("invoice_url"))

        return render_template("create_label.html")

    # ----------------------- NOWPAYMENTS IPN -----------------------

    @app.route("/nowpayments/ipn", methods=["POST"])
    @limiter.limit("30 per minute")
    def nowpayments_ipn():
        raw_body = request.data or b""
        signature = request.headers.get("x-nowpayments-sig", "")

        if not verify_nowpayments_signature(raw_body, signature):
            current_app.logger.warning("NOWPayments IPN: invalid signature")
            return "invalid signature", 400

        try:
            data = request.get_json(force=True, silent=False)
        except Exception as e:
            current_app.logger.warning(f"NOWPayments IPN: invalid JSON: {e}")
            return "invalid json", 400

        payment_id = str(data.get("payment_id") or data.get("invoice_id") or "")
        payment_status = (data.get("payment_status") or "").lower()

        if not payment_id:
            return "missing payment_id", 400

        payment = Payment.query.filter_by(provider_payment_id=payment_id).first()
        if not payment:
            current_app.logger.warning(f"NOWPayments IPN: payment not found: {payment_id}")
            return "payment not found", 404

        success_statuses = {"finished", "confirmed", "paid", "completed"}

        if payment.type == "topup":
            if payment_status in success_statuses and payment.status != "paid":
                payment.status = "paid"
                user = User.query.get(payment.user_id)
                if user:
                    user.balance_usd = (user.balance_usd or 0.0) + payment.amount_usd
                    log_wallet_change(user, payment.amount_usd, "Wallet top-up via NOWPayments")
                db.session.commit()

                # Email
                try:
                    if user:
                        send_email(
                            subject="Your CryptoParcel wallet was topped up",
                            to_email=user.email,
                            html_body=f"<p>Your wallet was credited ${payment.amount_usd:.2f}.</p>",
                            text_body=f"Your wallet was credited ${payment.amount_usd:.2f}.",
                        )
                except Exception:
                    pass

        elif payment.type == "label":
            if payment_status in success_statuses and payment.status != "paid":
                payment.status = "paid"
                order = Order.query.get(payment.order_id)
                if order:
                    order.status = "paid"
                    db.session.commit()
                    # Email
                    try:
                        user = User.query.get(order.user_id)
                        if user:
                            send_email(
                                subject="Your CryptoParcel label is paid",
                                to_email=user.email,
                                html_body=f"<p>Your label #{order.id} has been paid via crypto.</p>",
                                text_body=f"Your label #{order.id} has been paid via crypto.",
                            )
                    except Exception:
                        pass
                else:
                    db.session.commit()

        return "ok", 200

    # ----------------------- ADMIN -----------------------

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if is_admin():
            return redirect(url_for("admin_dashboard"))

        if request.method == "POST":
            password = request.form.get("password") or ""
            admin_env_password = os.getenv("ADMIN_PASSWORD", "")
            if admin_env_password and password == admin_env_password:
                session["admin_auth"] = True
                flash("Admin session unlocked.", "success")
                return redirect(url_for("admin_dashboard"))
            flash("Invalid admin password.", "error")
            return redirect(url_for("admin_login"))

        return render_template("admin/login.html")

    @app.route("/admin/logout")
    @admin_required
    def admin_logout():
        session.pop("admin_auth", None)
        flash("Admin session cleared.", "info")
        return redirect(url_for("index"))

    @app.route("/admin")
    @admin_required
    def admin_dashboard():
        run_auto_cleanup()
        total_users = User.query.count()
        total_orders = Order.query.count()
        total_payments = Payment.query.count()
        total_wallet_balance = db.session.query(db.func.coalesce(db.func.sum(User.balance_usd), 0.0)).scalar()
        recent_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
        recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(10).all()
        return render_template(
            "admin/dashboard.html",
            total_users=total_users,
            total_orders=total_orders,
            total_payments=total_payments,
            total_wallet_balance=total_wallet_balance,
            recent_orders=recent_orders,
            recent_payments=recent_payments,
        )

    @app.route("/admin/orders")
    @admin_required
    def admin_orders():
        status = request.args.get("status")
        q = Order.query
        if status:
            q = q.filter_by(status=status)
        orders = q.order_by(Order.created_at.desc()).limit(100).all()
        return render_template("admin/orders.html", orders=orders, filter_status=status)

    @app.route("/admin/orders/<int:order_id>/delete", methods=["POST"])
    @admin_required
    def admin_delete_order(order_id):
        order = Order.query.get_or_404(order_id)
        Payment.query.filter_by(order_id=order.id).delete()
        db.session.delete(order)
        db.session.commit()
        flash(f"Order #{order_id} deleted.", "success")
        return redirect(url_for("admin_orders"))

    @app.route("/admin/orders/<int:order_id>/cancel", methods=["POST"])
    @admin_required
    def admin_cancel_order(order_id):
        order = Order.query.get_or_404(order_id)
        if order.status not in ("paid", "cancelled", "cancelled_auto"):
            order.status = "cancelled_admin"
            db.session.commit()
            flash(f"Order #{order_id} cancelled.", "info")
        else:
            flash("Order is already finalized and cannot be cancelled.", "error")
        return redirect(url_for("admin_orders"))

    @app.route("/admin/payments")
    @admin_required
    def admin_payments():
        ptype = request.args.get("type")
        q = Payment.query
        if ptype:
            q = q.filter_by(type=ptype)
        payments = q.order_by(Payment.created_at.desc()).limit(100).all()
        return render_template("admin/payments.html", payments=payments, filter_type=ptype)

    @app.route("/admin/payments/<int:payment_id>/delete", methods=["POST"])
    @admin_required
    def admin_delete_payment(payment_id):
        payment = Payment.query.get_or_404(payment_id)
        db.session.delete(payment)
        db.session.commit()
        flash(f"Payment #{payment_id} deleted.", "success")
        return redirect(url_for("admin_payments"))

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        users = User.query.order_by(User.created_at.desc()).limit(100).all()
        return render_template("admin/users.html", users=users)

    @app.route("/admin/users/<int:user_id>/adjust_balance", methods=["POST"])
    @admin_required
    def admin_adjust_balance(user_id):
        user = User.query.get_or_404(user_id)
        delta_str = request.form.get("delta") or "0"
        reason = (request.form.get("reason") or "Manual adjustment by admin").strip()
        try:
            delta = float(delta_str)
        except ValueError:
            flash("Invalid amount.", "error")
            return redirect(url_for("admin_users"))

        user.balance_usd = (user.balance_usd or 0.0) + delta
        log_wallet_change(user, delta, reason)
        db.session.commit()
        flash(f"Updated balance for {user.email} by {delta:.2f}.", "success")
        return redirect(url_for("admin_users"))

    @app.route("/admin/cleanup", methods=["POST"])
    @admin_required
    def admin_cleanup():
        run_auto_cleanup()
        flash("Auto cleanup executed.", "success")
        return redirect(url_for("admin_dashboard"))

    # ----------------------- ERROR HANDLERS -----------------------

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        current_app.logger.error(f"Server error: {e}")
        return render_template("errors/500.html"), 500


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)), debug=True)
