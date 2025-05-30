from flask import Flask
from flask_migrate import Migrate, upgrade
from models import db, User, Survey, Question, SurveyResponse, Answer
import os

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oliver_ads.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    migrate = Migrate(app, db)
    
    return app

def run_migrations():
    app = create_app()
    with app.app_context():
        # Run any pending migrations
        upgrade()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', is_admin=True)
            admin.set_password('admin')
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    run_migrations() 