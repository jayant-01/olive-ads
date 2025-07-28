#!/usr/bin/env python3
"""
Script to update existing surveys with new external form fields.
This ensures all existing surveys are marked as AI-generated and have the proper form_type.
"""

from app import app, db
from models import Survey

def update_existing_surveys():
    """Update all existing surveys to have the new external form fields."""
    with app.app_context():
        # Get all existing surveys
        surveys = Survey.query.all()
        
        print(f"Found {len(surveys)} existing surveys to update...")
        
        for survey in surveys:
            # Set default values for existing surveys
            if not hasattr(survey, 'is_external') or survey.is_external is None:
                survey.is_external = False
                print(f"Updated survey '{survey.title}' - set is_external = False")
            
            if not hasattr(survey, 'form_type') or survey.form_type is None:
                survey.form_type = 'ai_generated'
                print(f"Updated survey '{survey.title}' - set form_type = 'ai_generated'")
            
            if not hasattr(survey, 'external_url') or survey.external_url is None:
                survey.external_url = None
                print(f"Updated survey '{survey.title}' - set external_url = None")
        
        # Commit all changes
        try:
            db.session.commit()
            print("✅ Successfully updated all existing surveys!")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Error updating surveys: {e}")

if __name__ == "__main__":
    update_existing_surveys() 