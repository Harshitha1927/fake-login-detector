"""
Production WSGI entry point for hosting on Render, Railway, PythonAnywhere, or Heroku.
"""
from app import app

if __name__ == "__main__":
    app.run()
