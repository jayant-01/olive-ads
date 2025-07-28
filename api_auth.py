from functools import wraps
from flask import request, jsonify
from models import APIKey, db
from datetime import datetime

def require_api_key(f):
    """Decorator to require API key authentication for endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from headers
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Find the API key in database
        api_key_obj = APIKey.query.filter_by(is_active=True).first()
        if not api_key_obj:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Check if the provided key matches
        if not api_key_obj.check_key(api_key):
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Update last used timestamp
        api_key_obj.last_used = datetime.utcnow()
        db.session.commit()
        
        # Add API key object to request context
        request.api_key = api_key_obj
        
        return f(*args, **kwargs)
    return decorated_function

def get_api_key_from_request():
    """Helper function to get API key from request headers."""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return None
    
    # Find the API key in database
    api_key_obj = APIKey.query.filter_by(is_active=True).first()
    if not api_key_obj or not api_key_obj.check_key(api_key):
        return None
    
    return api_key_obj 