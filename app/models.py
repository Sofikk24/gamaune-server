from . import db
from datetime import datetime


# --- Пользователь (админ или обычный) ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(256))   # Храним только хэш!
    role = db.Column(db.String(20), default='user')  # 'user' или 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # заявки этого пользователя
    applications = db.relationship('Applicant', backref='user', lazy=True)


# --- Заявитель (форма заявки на предмет) ---
class Applicant(db.Model):
    __tablename__ = 'applicant'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(50))
    email = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # все заявки могут быть связаны с зарегистрированным пользователем

    # связь с артефактами, которые подал этот заявитель
    artifacts = db.relationship('Artifact', backref='applicant', lazy=True)


# --- Автор (создатель предмета) ---
class Author(db.Model):
    __tablename__ = 'author'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255))
    birth_date = db.Column(db.String(100))
    place_of_residence = db.Column(db.String(255))
    additional_info = db.Column(db.Text)

    # Связь: автор может быть у многих артефактов
    artifacts = db.relationship('Artifact', backref='author', lazy=True)


# --- Категория (направление, тип, эпоха) ---
class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    # Связь: категория у многих артефактов
    artifacts = db.relationship('Artifact', backref='category', lazy=True)


# --- Временной период ---
class Period(db.Model):
    __tablename__ = 'period'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    # Связь: период у многих артефактов
    artifacts = db.relationship('Artifact', backref='period', lazy=True)


# --- География ---
class Geography(db.Model):
    __tablename__ = 'geography'
    id = db.Column(db.Integer, primary_key=True)
    region = db.Column(db.String(100))
    city = db.Column(db.String(100))
    country = db.Column(db.String(100))
    # Связь: география у многих артефактов
    artifacts = db.relationship('Artifact', backref='geography', lazy=True)


# --- Артефакт (рукотворный предмет) ---
class Artifact(db.Model):
    __tablename__ = 'artifact'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    materials = db.Column(db.String(255))
    technique = db.Column(db.String(255))
    creation_date = db.Column(db.String(50))
    story = db.Column(db.Text)
    photo_url = db.Column(db.String(255))
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'

    # связи с другими таблицами
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('author.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    period_id = db.Column(db.Integer, db.ForeignKey('period.id'))
    geography_id = db.Column(db.Integer, db.ForeignKey('geography.id'))

    # связанные файлы (фото, документы)
    files = db.relationship('File', backref='artifact', lazy=True)


# --- Файлы (фото, pdf) ---
class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    artifact_id = db.Column(db.Integer, db.ForeignKey('artifact.id'))
    file_type = db.Column(db.String(50))
    file_url = db.Column(db.String(255))


# --- Аналитика (минимально: посещения страниц и заявки) ---
class Visit(db.Model):
    __tablename__ = 'visit'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45))
    visit_time = db.Column(db.DateTime, default=datetime.utcnow)
    page = db.Column(db.String(128))
    user_agent = db.Column(db.String(256))
    # можно добавить user_id если хочешь отслеживать авторизованных

class ApplicationLog(db.Model):
    __tablename__ = 'application_log'
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('applicant.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(30))   # например, 'submitted', 'approved', 'rejected'
    comment = db.Column(db.Text)

    applicant = db.relationship('Applicant')
