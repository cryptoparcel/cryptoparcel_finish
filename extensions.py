from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Shared database instance
db = SQLAlchemy()

# Shared login manager
login_manager = LoginManager()
login_manager.login_view = "login"

# Shared rate limiter (in-memory is OK for local dev)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)
