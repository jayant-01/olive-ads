import requests
import json
from datetime import datetime
from models import db, PostbackConfig, PostbackLog
from jinja2 import Template
import logging

logger = logging.getLogger(__name__)

class PostbackService:
    @staticmethod
    def process_survey_response(response):
        """Process postbacks for a survey response."""
        # Get active postback configurations for this survey
        configs = PostbackConfig.query.filter_by(survey_id=response.survey_id, is_active=True).all()
        
        for config in configs:
            try:
                # Prepare payload data
                payload_data = {
                    'survey_id': response.survey_id,
                    'survey_title': response.survey.title,
                    'response_id': response.id,
                    'respondent_id': response.respondent_id,
                    'submitted_at': response.created_at.isoformat(),
                    'answers': [
                        {
                            'question_id': answer.question_id,
                            'question_text': answer.question.question_text,
                            'answer': answer.answer_text
                        }
                        for answer in response.answers
                    ]
                }
                
                # Format payload using template
                try:
                    payload = config.payload_template.format(**payload_data)
                except KeyError as e:
                    raise ValueError(f"Invalid template variable: {str(e)}")
                
                # Send postback request
                headers = config.headers or {}
                if 'Content-Type' not in headers:
                    headers['Content-Type'] = 'application/json'
                
                response = requests.request(
                    method=config.method,
                    url=config.url,
                    headers=headers,
                    data=payload
                )
                
                # Log the postback attempt
                log = PostbackLog(
                    config_id=config.id,
                    response_id=response.id,
                    status_code=response.status_code,
                    response_text=response.text,
                    sent_at=datetime.utcnow()
                )
                db.session.add(log)
                db.session.commit()
                
            except Exception as e:
                # Log the error
                log = PostbackLog(
                    config_id=config.id,
                    response_id=response.id,
                    status_code=None,
                    response_text=str(e),
                    sent_at=datetime.utcnow()
                )
                db.session.add(log)
                db.session.commit()
    
    @staticmethod
    def test_postback(config, test_data):
        """Test a postback configuration with sample data."""
        try:
            # Format payload using template
            try:
                payload = config.payload_template.format(**test_data)
            except KeyError as e:
                raise ValueError(f"Invalid template variable: {str(e)}")
            
            # Send test request
            headers = config.headers or {}
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
            
            response = requests.request(
                method=config.method,
                url=config.url,
                headers=headers,
                data=payload
            )
            
            return {
                'status_code': response.status_code,
                'response_text': response.text
            }
            
        except Exception as e:
            return {
                'error': str(e)
            } 