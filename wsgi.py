"""WSGI entry point for production servers (gunicorn, PythonAnywhere, etc.)."""
from app import app as application  # noqa: F401
