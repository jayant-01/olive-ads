import google.generativeai as genai
import json
import os
from dotenv import load_dotenv

load_dotenv()

# Configure the Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

def generate_survey_from_prompt(prompt):
    """
    Generate a survey structure from a prompt using Gemini
    """
    model = genai.GenerativeModel('gemini-2.0-flash')
    
    system_prompt = """
    You are a survey generation expert. Given a prompt, create a survey structure in JSON format.
    The survey should include:
    1. A title
    2. A description
    3. A list of questions with:
       - question_text (string)
       - question_type (one of: "text", "multiple_choice", "checkbox")
       - options (array of strings, required for multiple_choice and checkbox)
       - is_required (boolean)
       - order (integer)
    
    Example format:
    {
        "title": "Customer Feedback Survey",
        "description": "Please help us improve our services",
        "questions": [
            {
                "question_text": "How satisfied are you with our service?",
                "question_type": "multiple_choice",
                "options": ["Very Satisfied", "Satisfied", "Neutral", "Dissatisfied", "Very Dissatisfied"],
                "is_required": true,
                "order": 1
            }
        ]
    }
    
    Return ONLY the JSON structure, no additional text or markdown formatting.
    """
    
    try:
        response = model.generate_content([system_prompt, prompt])
        response_text = response.text.strip()
        
        # Remove any markdown code block formatting if present
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        survey_data = json.loads(response_text)
        return survey_data
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {str(e)}")
        print(f"Raw response: {response_text}")
        return None
    except Exception as e:
        print(f"Error generating survey: {str(e)}")
        return None

def validate_survey_structure(survey_data):
    """
    Validate the generated survey structure
    """
    required_fields = ['title', 'description', 'questions']
    if not all(field in survey_data for field in required_fields):
        return False
    
    for question in survey_data['questions']:
        required_question_fields = ['question_text', 'question_type', 'is_required', 'order']
        if not all(field in question for field in required_question_fields):
            return False
        
        if question['question_type'] in ['multiple_choice', 'checkbox'] and 'options' not in question:
            return False
    
    return True 