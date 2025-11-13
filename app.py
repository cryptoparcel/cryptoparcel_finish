from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, jsonify
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os, io, requests, hmac, hashlib

from config import Config
from label_generator import generate_shipping_label_pdf

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

# Import database + models
from models import db, User, Order, Payment

login_manager = LoginManager()
login_manager.login_view = "login"

# Rate limiter
limiter = Limiter(get_remote_address, storage_uri="memory://")


# -------------------------------------------------------------------------
# Helper: Price calculation (placeholder until we add real carrier APIs)
# -------------------------------------------------------------------------
def calculate_label_price(carrier, service, weight_oz):
    """
    Simple placeholder rate logic.
    Later replaced with API calls (USPS, UPS, FedEx).
    """
    base_price = 3.00
    per_oz = 0.10

    fast_keywords = ["Express", "Overnight", "Priority", "Next Day", "2Day"]
    if any(k.lower() in service.lower() for k in fast_keywords):
        base_price += 2.00

    return round(base_price + weight_oz * per_oz, 2)


# -------------------------------------------------------------------------
# App Factory
# -------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

    # Security headers
    @app.after_request
    def add_headers(response):
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
        db.create_all()

    register_routes(app)
    return app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------------
def register_routes(app):

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    # ---------------------- REGISTER --------------------------
    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")

            if not email or not password:
                flash("Email and password are required.", "error")
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

            flash("Account created!", "success")
            return redirect(url_for("login"))

        return render_template("auth/register.html")

    # ---------------------- LOGIN --------------------------
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").lower()
            password = request.form.get("password", "")

            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid email or password.", "error")
                return redirect(url_for("login"))

            login_user(user)
            return redirect(url_for("dashboard"))

        return render_template("auth/login.html")

    # ---------------------- LOGOUT --------------------------
    @app.route("/logout")
    def logout():
        logout_user()
        return redirect(url_for("index"))

    # ---------------------- DASHBOARD --------------------------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).limit(10).all()
        return render_template("dashboard.html", orders=orders)

    # ---------------------- ORDERS --------------------------
    @app.route("/orders")
    @login_required
    def orders():
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.id.desc()).all()
        return render_template("orders.html", orders=orders)

    # ---------------------- WALLET --------------------------
    @app.route("/wallet")
    @login_required
    def wallet():
        topups = (
            Payment.query.filter_by(user_id=current_user.id, type="topup")
            .order_by(Payment.created_at.desc())
            .limit(20)
            .all()
        )
        return render_template("wallet.html", balance=current_user.balance_usd, topups=topups)

    @app.route("/wallet/topup", methods=["GET", "POST"])
    @login_required
    def wallet_topup():
        if request.method == "POST":
            amount_str = request.form.get("amount_usd", "0")
            try:
                amount = float(amount_str)
            except ValueError:
                flash("Invalid amount.", "error")
                return redirect(url_for("wallet_topup"))

            if amount <= 0 or amount > 5000:
                flash("Amount must be between 1–5000 USD.", "error")
                return redirect(url_for("wallet_topup"))

            # Create a pending Payment entry
            payment = Payment(
                user_id=current_user.id,
                type="topup",
                amount_usd=amount,
                currency="crypto",
                status="waiting",
            )
            db.session.add(payment)
            db.session.commit()

            # Create invoice
            invoice = create_topup_invoice(payment)
            payment.provider = "nowpayments"
            payment.provider_payment_id = invoice.get("id")
            db.session.commit()

            return redirect(invoice.get("invoice_url"))

        return render_template("wallet_topup.html")

    # -------------------------------------------------------------------------
    # LABEL CREATION (Wallet-first logic + Crypto fallback)
    # -------------------------------------------------------------------------
    @app.route("/create-label", methods=["GET", "POST"])
    @login_required
    def create_label():
        if request.method == "POST":
            service = request.form.get("service", "USPS First-Class")

            # Infer carrier
            if service.startswith("USPS"):
                carrier = "USPS"
            elif service.startswith("UPS"):
                carrier = "UPS"
            elif service.startswith("FedEx"):
                carrier = "FedEx"
            else:
                carrier = "Custom"

            # Weight
            try:
                weight_oz = float(request.form.get("weight_oz", "0"))
            except ValueError:
                flash("Invalid weight.", "error")
                return redirect(url_for("create_label"))

            if weight_oz <= 0:
                flash("Weight must be greater than 0.", "error")
                return redirect(url_for("create_label"))

            # Structured address
            fa_name = request.form.get("from_name", "")
            fa_street1 = request.form.get("from_street1", "")
            fa_city = request.form.get("from_city", "")
            fa_state = request.form.get("from_state", "")
            fa_zip = request.form.get("from_zip", "")

            ta_name = request.form.get("to_name", "")
            ta_street1 = request.form.get("to_street1", "")
            ta_city = request.form.get("to_city", "")
            ta_state = request.form.get("to_state", "")
            ta_zip = request.form.get("to_zip", "")

            if not all([fa_name, fa_street1, fa_city, fa_state, fa_zip]):
                flash("From address incomplete.", "error")
                return redirect(url_for("create_label"))

            if not all([ta_name, ta_street1, ta_city, ta_state, ta_zip]):
                flash("To address incomplete.", "error")
                return redirect(url_for("create_label"))

            from_address = f"{fa_name}\n{fa_street1}\n{fa_city}, {fa_state} {fa_zip}\nUnited States"
            to_address = f"{ta_name}\n{ta_street1}\n{ta_city}, {ta_state} {ta_zip}\nUnited States"

            # Calculate price
            amount_usd = calculate_label_price(carrier, service, weight_oz)

            # Create order
            order = Order(
                user_id=current_user.id,
                carrier=carrier,
                service=service,
                weight_oz=weight_oz,
                from_address=from_address,
                to_address=to_address,
                amount_usd=amount_usd,
                status="pending_payment",
            )
            db.session.add(order)
            db.session.commit()

            # WALLET-FIRST LOGIC
            if current_user.balance_usd >= amount_usd:
                current_user.balance_usd -= amount_usd
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
                db.session.commit()

                flash("Label paid with your wallet balance!", "success")
                return redirect(url_for("order_detail", order_id=order.id))

            # CRYPTO FALLBACK
            invoice = create_nowpayments_invoice(order)

            payment = Payment(
                order_id=order.id,
                user_id=current_user.id,
                type="label",
                provider="nowpayments",
                provider_payment_id=str(invoice.get("id")),
                amount_usd=amount_usd,
                currency="crypto",
                status="waiting",
            )
            db.session.add(payment)
            db.session.commit()

            return redirect(invoice["invoice_url"])

        return render_template("create_label.html")

    # ---------------------- ORDER DETAIL --------------------------
    @app.route("/orders/<int:order_id>")
    @login_required
    def order_detail(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id:
            flash("Unauthorized", "error")
            return redirect(url_for("orders"))
        return render_template("order_detail.html", order=order)

    # ---------------------- DOWNLOAD LABEL --------------------------
    @app.route("/orders/<int:order_id>/label")
    @login_required
    def download_label(order_id):
        order = Order.query.get_or_404(order_id)
        if order.user_id != current_user.id:
            flash("Unauthorized", "error")
            return redirect(url_for("orders"))

        if order.status != "paid":
            flash("Payment required.", "error")
            return redirect(url_for("orders"))

        pdf_bytes = generate_shipping_label_pdf(order)
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"label_{order.id}.pdf",
        )

    # ---------------------- PAYMENT CALLBACK --------------------------
    @app.route("/nowpayments/ipn", methods=["POST"])
    @limiter.limit("30 per minute")
    def nowpayments_ipn():
        raw = request.data
        sig = request.headers.get("x-nowpayments-sig", "")

        if not verify_nowpayments_signature(raw, sig):
            return "invalid", 400

        data = request.json
        payment_id = data.get("payment_id")
        payment_status = data.get("payment_status")

        payment = Payment.query.filter_by(provider_payment_id=str(payment_id)).first()
        if not payment:
            return "payment not found", 404

        if payment.type == "topup":
            if payment_status in ["confirmed", "finished", "paid"]:
                payment.status = "paid"
                current_user_obj = User.query.get(payment.user_id)
                current_user_obj.balance_usd += payment.amount_usd
                db.session.commit()

        elif payment.type == "label":
            if payment_status in ["confirmed", "finished", "paid"]:
                payment.status = "paid"
                order = Order.query.get(payment.order_id)
                order.status = "paid"
                db.session.commit()

        return "ok", 200

    # ---------------------- API HELPERS --------------------------
    def verify_nowpayments_signature(raw_body, signature):
        secret = os.getenv("NOWPAYMENTS_IPN_SECRET", "")
        expected = hmac.new(secret.encode(), raw_body, hashlib.sha512).hexdigest()
        return hmac.compare_digest(expected, signature)

    def create_nowpayments_invoice(order):
        api_key = os.getenv("NOWPAYMENTS_API_KEY")
        url = f"{os.getenv('NOWPAYMENTS_BASE_URL')}/v1/invoice"

        payload = {
            "price_amount": order.amount_usd,
            "price_currency": "usd",
            "order_id": order.id,
            "pay_currency": "btc",
            "success_url": url_for("order_detail", order_id=order.id, _external=True),
            "cancel_url": url_for("orders", _external=True),
        }

        r = requests.post(url, json=payload, headers={"x-api-key": api_key})
        return r.json()

    def create_topup_invoice(payment):
        api_key = os.getenv("NOWPAYMENTS_API_KEY")
        url = f"{os.getenv('NOWPAYMENTS_BASE_URL')}/v1/invoice"

        payload = {
            "price_amount": payment.amount_usd,
            "price_currency": "usd",
            "order_id": f"topup-{payment.id}",
            "pay_currency": "btc",
            "success_url": url_for("wallet", _external=True),
            "cancel_url": url_for("wallet", _external=True),
        }

        r = requests.post(url, json=payload, headers={"x-api-key": api_key})
        return r.json()


# -------------------------------------------------------------------------
# Run app
# -------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
