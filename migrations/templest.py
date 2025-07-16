"""
Создание таблички
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
"""
from app import create_app, db

app = create_app()
with app.app_context():
    db.create_all()
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    print(inspector.get_table_names())
