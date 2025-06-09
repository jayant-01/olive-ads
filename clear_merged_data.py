from app import app, db
from models import Survey  # or from app import Survey if it's imported there

def clear_merged_user_data_dict_entries():
    surveys = Survey.query.all()
    count = 0
    for s in surveys:
        if isinstance(s.merged_user_data, dict):
            s.merged_user_data = []  # reset to empty list
            count += 1
    db.session.commit()
    print(f"Cleared merged_user_data for {count} surveys.")

if __name__ == "__main__":
    with app.app_context():
        clear_merged_user_data_dict_entries()
