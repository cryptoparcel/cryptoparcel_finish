from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    send_file,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from io import BytesIO
import os
import json
import hmac
import hashlib
import requests

from config import Config
from label_generator import generate_shipping_label_pdf

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        from models import User, Order, Payment  # noqa: F401
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


def create_nowpayments_invoice(order, pay_currency="btc"):
    if not Config.NOWPAYMENTS_API_KEY:
        raise RuntimeError("NOWPayments API key is not configured")

    base_url = Config.NOWPAYMENTS_BASE_URL.rstrip("/")
    endpoint = f"{base_url}/v1/invoice"

    success_url = url_for("payment_success", order_id=order.id, _external=True)
    cancel_url = url_for("payment_cancel", order_id=order.id, _external=True)
    ipn_url = url_for("nowpayments_ipn", _external=True)

    payload = {
        "price_amount": float(order.amount_usd),
        "price_currency": "usd",
        "order_id": str(order.id),
        "order_description": f"CryptoParcel shipping label #{order.id}",
        "ipn_callback_url": ipn_url,
        "success_url": success_url,
        "cancel_url": cancel_url,
    }

    headers = {
        "x-api-key": Config.NOWPAYMENTS_API_KEY,
        "Content-Type": "application/json",
    }

    resp = requests.post(endpoint, headers=headers, json=payload, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"NOWPayments error: {resp.status_code} {resp.text}")

    data = resp.json()
    if "invoice_url" not in data:
        raise RuntimeError(f"NOWPayments: invoice_url not in response: {data}")

    return data


def verify_nowpayments_signature(raw_body: str, signature: str) -> bool:
    if not Config.NOWPAYMENTS_IPN_SECRET:
        return False

    try:
        data = json.loads(raw_body or "{}")
    except ValueError:
        return False

    sorted_body = json.dumps(data, sort_keys=True, separators=(",", ":"))
    computed = hmac.new(
        Config.NOWPAYMENTS_IPN_SECRET.encode("utf-8"),
        sorted_body.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()

    return hmac.compare_digest(computed, signature or "")


def register_routes(app):
    from models import User, Order, Payment

    @app.route("/health")
    def health():
        return {"status": "ok"}, 200

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")

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

            hashed = generate_password_hash(password)
            user = User(email=email, password_hash=hashed)
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("auth/register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid email or password.", "error")
                return redirect(url_for("login"))

            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))

        return render_template("auth/login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        flash("Logged out.", "success")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        orders = (
            Order.query.filter_by(user_id=current_user.id)
            .order_by(Order.created_at.desc())
            .limit(5)
            .all()
        )
        return render_template("dashboard.html", orders=orders)

    @app.route("/orders")
    @login_required
    def orders():
        orders = (
            Order.query.filter_by(user_id=current_user.id)
            .order_by(Order.created_at.desc())
            .all()
        )
        return render_template("orders.html", orders=orders)

    @app.route("/create-label", methods=["GET", "POST"])
    @login_required
    def create_label():
        if request.method == "POST":
            carrier = request.form.get("carrier") or "USPS"
            service = request.form.get("service") or "Ground"
            weight_oz = request.form.get("weight_oz") or "0"
            from_address = request.form.get("from_address") or ""
            to_address = request.form.get("to_address") or ""
            reference = request.form.get("reference")

            try:
                weight_oz = float(weight_oz)
            except ValueError:
                flash("Invalid weight.", "error")
                return redirect(url_for("create_label"))

            if not from_address.strip() or not to_address.strip():
                flash("From and To address are required.", "error")
                return redirect(url_for("create_label"))

            base_price = 3.00
            per_oz = 0.10
            amount_usd = round(base_price + weight_oz * per_oz, 2)

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

            try:
                invoice = create_nowpayments_invoice(order)
            except Exception:
                order.status = "payment_error"
                db.session.commit()
                flash(
                    "There was a problem creating the crypto payment. "
                    "Please try again or contact support.",
                    "error",
                )
                return redirect(url_for("order_detail", order_id=order.id))

            payment = Payment(
                order_id=order.id,
                provider="nowpayments",
                provider_payment_id=str(invoice.get("payment_id") or invoice.get("id") or ""),
                amount_usd=order.amount_usd,
                currency="crypto",
                status="waiting",
            )
            db.session.add(payment)
            db.session.commit()

            invoice_url = invoice["invoice_url"]
            return redirect(invoice_url)

        return render_template("create_label.html")

    @app.route("/orders/<int:order_id>")
    @login_required
    def order_detail(order_id):
        order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
        return render_template("order_detail.html", order=order)

    @app.route("/orders/<int:order_id>/label")
    @login_required
    def download_label(order_id):
        order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()

        if order.status not in ("paid", "finished", "confirmed"):
            flash(
                "Your payment is still processing. The label will be available once "
                "NOWPayments confirms the payment.",
                "error",
            )
            return redirect(url_for("order_detail", order_id=order.id))

        pdf_bytes = generate_shipping_label_pdf(order)
        return send_file(
            BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"label_{order.id}.pdf",
        )

    @app.route("/payment/success/<int:order_id>")
    def payment_success(order_id):
        order = Order.query.get_or_404(order_id)
        return render_template("payment_success.html", order=order)

    @app.route("/payment/cancel/<int:order_id>")
    def payment_cancel(order_id):
        order = Order.query.get_or_404(order_id)
        if order.status == "pending_payment":
            order.status = "cancelled"
            db.session.commit()
        flash("Payment cancelled.", "error")
        return render_template("payment_cancel.html", order=order)

    @app.route("/nowpayments/ipn", methods=["POST"])
    def nowpayments_ipn():
        raw_body = request.get_data(as_text=True)
        sig = request.headers.get("x-nowpayments-sig", "")

        if not verify_nowpayments_signature(raw_body, sig):
            return "invalid signature", 400

        try:
            data = json.loads(raw_body)
        except ValueError:
            return "invalid json", 400

        order_id = data.get("order_id")
        payment_status = data.get("payment_status")
        price_amount = data.get("price_amount")
        pay_currency = data.get("pay_currency")
        payment_id = data.get("payment_id") or data.get("id")

        if not order_id:
            return "missing order_id", 400

        try:
            order_id_int = int(order_id)
        except ValueError:
            return "bad order_id", 400

        order = Order.query.get(order_id_int)
        if not order:
            return "order not found", 404

        payment = (
            Payment.query.filter_by(order_id=order.id, provider="nowpayments")
            .order_by(Payment.created_at.desc())
            .first()
        )
        if not payment:
            payment = Payment(
                order_id=order.id,
                provider="nowpayments",
                provider_payment_id=str(payment_id or ""),
                amount_usd=price_amount or order.amount_usd,
                currency=pay_currency or "crypto",
            )
            db.session.add(payment)

        payment.status = payment_status or payment.status
        payment.currency = pay_currency or payment.currency
        if price_amount:
            try:
                payment.amount_usd = float(price_amount)
            except ValueError:
                pass

        success_statuses = {"finished", "confirmed", "paid"}
        pending_statuses = {"waiting", "confirming", "sending", "partially_paid"}

        if payment_status in success_statuses:
            order.status = "paid"
        elif payment_status in pending_statuses:
            if order.status not in ("paid", "payment_error"):
                order.status = "pending_payment"
        else:
            if order.status != "paid":
                order.status = "payment_failed"

        db.session.commit()
        return jsonify({"ok": True})


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)), debug=True)
