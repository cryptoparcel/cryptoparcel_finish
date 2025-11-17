from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Single, shared database object for the whole app
db = SQLAlchemy()

# Single, shared login manager
login_manager = LoginManager()
login_manager.login_view = "login"

# Single, shared rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)
