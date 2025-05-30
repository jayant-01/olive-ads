# Oliver Ads Survey Application

A Flask-based survey application with AI-powered survey generation.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:
Create a `.env` file with:
```
GEMINI_API_KEY=your_gemini_api_key_here
```

3. Initialize the database:
```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

## Database Migrations

When making changes to the database models:

1. Create a new migration:
```bash
flask db migrate -m "Description of changes"
```

2. Review the generated migration file in the `migrations/versions` directory

3. Apply the migration:
```bash
flask db upgrade
```

## Running the Application

```bash
python app.py
```

## Default Admin Credentials

- Username: admin
- Password: admin

## Features

- User authentication
- AI-powered survey generation
- Multiple question types (text, multiple choice, checkbox)
- Survey response collection and analysis
- Admin dashboard
- User dashboard 