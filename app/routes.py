from flask import Blueprint, request, jsonify
from . import db
from .models import Artifact, Author, Applicant, Geography, Period, Category, File, User
from werkzeug.utils import secure_filename
from flask import current_app, send_from_directory
from flask_login import login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from functools import wraps
from app import login_manager
from sqlalchemy import or_
import os

main_bp = Blueprint('main', __name__)
bcrypt = Bcrypt()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Доступ запрещён: требуется авторизация администратора'}), 403
        return func(*args, **kwargs)
    return wrapper


@main_bp.route('/admin/artifacts/moderation', methods=['GET'])
@admin_required
def get_artifacts_for_moderation():
    """
    Получить экспонаты на модерации
    ---
    tags:
      - Модерация
    summary: Получить экспонаты на модерации
    description: Только для администратора! Возвращает все экспонаты со статусом 'pending'.
    responses:
      200:
        description: Список экспонатов на модерации
        schema:
          type: array
          items:
            type: object
            properties:
              id: {type: integer}
              name: {type: string}
              status: {type: string}
    """
    artifacts = Artifact.query.filter_by(status='pending').all()
    result = [{'id': a.id, 'name': a.name, 'status': a.status} for a in artifacts]
    return jsonify(result)


@main_bp.route('/admin/artifacts/<int:artifact_id>/approve', methods=['POST'])
@admin_required
def approve_artifact(artifact_id):
    """
    Одобрить экспонат
    ---
    tags:
      - Модерация
    summary: Одобрить экспонат
    description: Администратор одобряет публикацию экспоната.
    parameters:
      - in: path
        name: artifact_id
        type: integer
        required: true
        description: ID экспоната
    responses:
      200:
        description: Экспонат одобрен
        schema:
          type: object
          properties:
            message: {type: string}
    """
    artifact = Artifact.query.get_or_404(artifact_id)
    artifact.status = 'approved'
    db.session.commit()
    return jsonify({'message': 'Экспонат одобрен'})


@main_bp.route('/admin/artifacts/<int:artifact_id>/reject', methods=['POST'])
@admin_required
def reject_artifact(artifact_id):
    """
    Отклонить экспонат
    ---
    tags:
      - Модерация
    summary: Отклонить экспонат
    description: Администратор отклоняет публикацию экспоната.
    parameters:
      - in: path
        name: artifact_id
        type: integer
        required: true
        description: ID экспоната
    responses:
      200:
        description: Экспонат отклонён
        schema:
          type: object
          properties:
            message: {type: string}
    """
    artifact = Artifact.query.get_or_404(artifact_id)
    artifact.status = 'rejected'
    db.session.commit()
    return jsonify({'message': 'Экспонат отклонён'})


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Регистрация пользователя (user/admin) ---
@main_bp.route('/register', methods=['POST'])
def register():
    """
        Регистрация пользователя
        ---
        tags:
          - Авторизация
        summary: Регистрация пользователя
        description: Регистрирует нового пользователя с email, телефоном, паролем и ролью.
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [email, password, full_name, phone]
              properties:
                email: {type: string, example: "admin@mail.ru"}
                password: {type: string, example: "123456"}
                full_name: {type: string, example: "Администратор"}
                phone: {type: string, example: "+7 999 123-45-67"}
                role: {type: string, example: "admin"}
        responses:
          201:
            description: Пользователь успешно создан
            schema:
              type: object
              properties:
                message: {type: string}
          409:
            description: Email уже зарегистрирован
        """
    data = request.json
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    phone = data.get('phone')
    role = data.get('role', 'user')
    if not all([email, password, full_name, phone]):
        return jsonify({'error': 'Все поля обязательны'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email уже зарегистрирован'}), 409
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(email=email, full_name=full_name, phone=phone, password_hash=password_hash, role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Пользователь создан'}), 201


# --- Логин ---
@main_bp.route('/login', methods=['POST'])
def login():
    """
        Вход пользователя
        ---
        tags:
          - Авторизация
        summary: Вход пользователя
        description: Аутентификация пользователя по email и паролю.
        parameters:
          - in: body
            name: body
            schema:
              type: object
              required: [email, password]
              properties:
                email: {type: string, example: "admin@mail.ru"}
                password: {type: string, example: "123456"}
        responses:
          200:
            description: Успешный вход
            schema:
              type: object
              properties:
                message: {type: string}
                role: {type: string}
                full_name: {type: string}
          401:
            description: Неверный логин или пароль
        """
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        login_user(user)
        return jsonify({'message': 'Успешный вход', 'role': user.role, 'full_name': user.full_name})
    return jsonify({'error': 'Неверный логин или пароль'}), 401


# --- Логаут ---
@main_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
       Выход пользователя
       ---
       tags:
         - Авторизация
       summary: Выход пользователя
       description: Завершает сессию текущего пользователя (логаут).
       responses:
         200:
           description: Успешный выход
           schema:
             type: object
             properties:
               message: {type: string}
         401:
           description: Неавторизованный пользователь
       """
    logout_user()
    return jsonify({'message': 'Выход выполнен'})

# --- Проверка авторизации и роли ---
@main_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    """
        Профиль пользователя
        ---
        tags:
          - Авторизация
        summary: Получить профиль текущего пользователя
        description: Возвращает информацию о текущем авторизованном пользователе.
        responses:
          200:
            description: Информация о пользователе
            schema:
              type: object
              properties:
                id: {type: integer}
                full_name: {type: string}
                email: {type: string}
                phone: {type: string}
                role: {type: string}
          401:
            description: Неавторизованный пользователь
        """
    return jsonify({
        'id': current_user.id,
        'full_name': current_user.full_name,
        'email': current_user.email,
        'role': current_user.role
    })


@main_bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """
        Загрузить файл
        ---
        tags:
          - Файлы
        summary: Загрузить файл
        description: Загружает файл (изображение или PDF) и связывает его с экспонатом.
        consumes:
          - multipart/form-data
        parameters:
          - in: formData
            name: file
            type: file
            required: true
            description: Файл для загрузки (jpg, png, pdf)
          - in: formData
            name: artifact_id
            type: integer
            required: false
            description: ID экспоната, к которому относится файл
        responses:
          201:
            description: Файл успешно загружен
            schema:
              type: object
              properties:
                message: {type: string}
                file_id: {type: integer}
                file_url: {type: string}
          400:
            description: Ошибка загрузки файла
        """
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@main_bp.route('/upload', methods=['POST'])
def upload_file():
    """
        Загрузить файл
        ---
        tags:
          - Файлы
        summary: Загрузить файл
        description: Загружает файл (изображение или PDF) и связывает его с экспонатом.
        consumes:
          - multipart/form-data
        parameters:
          - in: formData
            name: file
            type: file
            required: true
            description: Файл для загрузки (jpg, png, pdf)
          - in: formData
            name: artifact_id
            type: integer
            required: false
            description: ID экспоната, к которому относится файл
        responses:
          201:
            description: Файл успешно загружен
            schema:
              type: object
              properties:
                message: {type: string}
                file_id: {type: integer}
                file_url: {type: string}
          400:
            description: Ошибка загрузки файла
        """
    if 'file' not in request.files:
        return jsonify({'error': 'Нет файла в запросе'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Файл не выбран'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'Недопустимый тип файла'}), 400

    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)  # на всякий случай

    file.save(os.path.join(upload_folder, filename))

    artifact_id = request.form.get('artifact_id', type=int)
    file_record = File(
        artifact_id=artifact_id,
        file_type=filename.rsplit('.', 1)[1].lower(),
        file_url=f"/uploads/{filename}"
    )
    db.session.add(file_record)
    db.session.commit()

    return jsonify({
        'message': 'Файл загружен',
        'file_id': file_record.id,
        'file_url': file_record.file_url
    }), 201


@main_bp.route('/applicants', methods=['GET'])
def get_applicants():
    """
        Получить список всех заявителей
        ---
        tags:
          - Заявители
        summary: Получить список всех заявителей
        description: Возвращает массив всех заявителей, подавших заявки.
        responses:
          200:
            description: Список заявителей
            schema:
              type: array
              items:
                type: object
                properties:
                  id: {type: integer}
                  full_name: {type: string}
                  phone: {type: string}
                  email: {type: string}
                  user_id: {type: integer}
        """
    applicants = Applicant.query.all()
    return jsonify([
        {
            'id': a.id,
            'full_name': a.full_name,
            'phone': a.phone,
            'email': a.email,
            'user_id': a.user_id
        } for a in applicants
    ])


@main_bp.route('/applicants', methods=['POST'])
def create_applicant():
    """
        Добавить нового заявителя
        ---
        tags:
          - Заявители
        summary: Добавить нового заявителя
        description: Создает нового заявителя для подачи заявки.
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [full_name]
              properties:
                full_name: {type: string, example: "Петров Иван"}
                phone: {type: string, example: "+7 999 123-45-67"}
                email: {type: string, example: "ivan@mail.ru"}
                user_id: {type: integer}
        responses:
          201:
            description: Заявитель успешно создан
            schema:
              type: object
              properties:
                message: {type: string}
                id: {type: integer}
        """
    data = request.json
    applicant = Applicant(
        full_name=data.get('full_name'),
        phone=data.get('phone'),
        email=data.get('email'),
        user_id=data.get('user_id')
    )
    db.session.add(applicant)
    db.session.commit()
    return jsonify({'message': 'Applicant created', 'id': applicant.id}), 201


@main_bp.route('/applicants/<int:applicant_id>', methods=['PUT'])
def update_applicant(applicant_id):
    """
        Обновить заявителя по id
        ---
        tags:
          - Заявители
        summary: Обновить заявителя по id
        description: Изменяет данные существующего заявителя.
        parameters:
          - in: path
            name: applicant_id
            type: integer
            required: true
            description: ID заявителя
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                full_name: {type: string}
                phone: {type: string}
                email: {type: string}
                user_id: {type: integer}
        responses:
          200:
            description: Заявитель успешно обновлён
            schema:
              type: object
              properties:
                message: {type: string}
        """
    applicant = Applicant.query.get_or_404(applicant_id)
    data = request.json
    applicant.full_name = data.get('full_name', applicant.full_name)
    applicant.phone = data.get('phone', applicant.phone)
    applicant.email = data.get('email', applicant.email)
    applicant.user_id = data.get('user_id', applicant.user_id)
    db.session.commit()
    return jsonify({'message': 'Applicant updated'})


@main_bp.route('/applicants/<int:applicant_id>', methods=['DELETE'])
def delete_applicant(applicant_id):
    """
        Удалить заявителя по id
        ---
        tags:
          - Заявители
        summary: Удалить заявителя по id
        description: Полностью удаляет заявителя из системы по его идентификатору.
        parameters:
          - in: path
            name: applicant_id
            type: integer
            required: true
            description: ID заявителя
        responses:
          200:
            description: Заявитель успешно удалён
            schema:
              type: object
              properties:
                message: {type: string}
          404:
            description: Заявитель не найден
        """
    applicant = Applicant.query.get_or_404(applicant_id)
    db.session.delete(applicant)
    db.session.commit()
    return jsonify({'message': 'Applicant deleted'})


@main_bp.route('/geographies', methods=['GET'])
def get_geographies():
    """
        Получить список всех географий
        ---
        tags:
          - География
        summary: Получить список всех географий
        description: Возвращает массив всех географических данных, связанных с экспонатами.
        responses:
          200:
            description: Список географий
            schema:
              type: array
              items:
                type: object
                properties:
                  id: {type: integer}
                  region: {type: string}
                  city: {type: string}
                  country: {type: string}
        """
    geographies = Geography.query.all()
    return jsonify([
        {
            'id': g.id,
            'region': g.region,
            'city': g.city,
            'country': g.country
        } for g in geographies
    ])


@main_bp.route('/geographies', methods=['POST'])
def create_geography():
    """
        Добавить новую географию
        ---
        tags:
          - География
        summary: Добавить новую географию
        description: Добавляет новую географическую область для привязки экспонатов.
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                region: {type: string, example: "Сибирь"}
                city: {type: string, example: "Томск"}
                country: {type: string, example: "Россия"}
        responses:
          201:
            description: География успешно создана
            schema:
              type: object
              properties:
                message: {type: string}
                id: {type: integer}
        """
    data = request.json
    geography = Geography(
        region=data.get('region'),
        city=data.get('city'),
        country=data.get('country')
    )
    db.session.add(geography)
    db.session.commit()
    return jsonify({'message': 'Geography created', 'id': geography.id}), 201


@main_bp.route('/geographies/<int:geography_id>', methods=['PUT'])
def update_geography(geography_id):
    """
        Обновить географию по id
        ---
        tags:
          - География
        summary: Обновить географию по id
        description: Изменяет данные существующей географии.
        parameters:
          - in: path
            name: geography_id
            type: integer
            required: true
            description: ID географии
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                region: {type: string}
                city: {type: string}
                country: {type: string}
        responses:
          200:
            description: География успешно обновлена
            schema:
              type: object
              properties:
                message: {type: string}
        """
    geography = Geography.query.get_or_404(geography_id)
    data = request.json
    geography.region = data.get('region', geography.region)
    geography.city = data.get('city', geography.city)
    geography.country = data.get('country', geography.country)
    db.session.commit()
    return jsonify({'message': 'Geography updated'})


@main_bp.route('/geographies/<int:geography_id>', methods=['DELETE'])
def delete_geography(geography_id):
    """
        Удалить географию по id
        ---
        tags:
          - География
        summary: Удалить географию по id
        description: Полностью удаляет географию из системы по ее идентификатору.
        parameters:
          - in: path
            name: geography_id
            type: integer
            required: true
            description: ID географии
        responses:
          200:
            description: География успешно удалена
            schema:
              type: object
              properties:
                message: {type: string}
          404:
            description: География не найдена
        """
    geography = Geography.query.get_or_404(geography_id)
    db.session.delete(geography)
    db.session.commit()
    return jsonify({'message': 'Geography deleted'})



@main_bp.route('/periods', methods=['GET'])
def get_periods():
    """
        Получить список всех периодов
        ---
        tags:
          - Периоды
        summary: Получить список всех периодов
        description: Возвращает массив всех исторических периодов, доступных в системе.
        responses:
          200:
            description: Список периодов
            schema:
              type: array
              items:
                type: object
                properties:
                  id: {type: integer}
                  name: {type: string}
        """
    periods = Period.query.all()
    return jsonify([{'id': p.id, 'name': p.name} for p in periods])

@main_bp.route('/periods', methods=['POST'])
def create_period():
    """
        Добавить новый период
        ---
        tags:
          - Периоды
        summary: Добавить новый период
        description: Создает новый исторический период для фильтрации экспонатов.
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string, example: "XX век"}
        responses:
          201:
            description: Период успешно создан
            schema:
              type: object
              properties:
                message: {type: string}
                id: {type: integer}
        """
    data = request.json
    period = Period(name=data.get('name'))
    db.session.add(period)
    db.session.commit()
    return jsonify({'message': 'Period created', 'id': period.id}), 201

@main_bp.route('/periods/<int:period_id>', methods=['PUT'])
def update_period(period_id):
    """
        Обновить период по id
        ---
        tags:
          - Периоды
        summary: Обновить период по id
        description: Изменяет название существующего периода.
        parameters:
          - in: path
            name: period_id
            type: integer
            required: true
            description: ID периода
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                name: {type: string}
        responses:
          200:
            description: Период успешно обновлён
            schema:
              type: object
              properties:
                message: {type: string}
        """
    period = Period.query.get_or_404(period_id)
    data = request.json
    period.name = data.get('name', period.name)
    db.session.commit()
    return jsonify({'message': 'Period updated'})

@main_bp.route('/periods/<int:period_id>', methods=['DELETE'])
def delete_period(period_id):
    """
        Удалить период по id
        ---
        tags:
          - Периоды
        summary: Удалить период по id
        description: Полностью удаляет период из системы по его идентификатору.
        parameters:
          - in: path
            name: period_id
            type: integer
            required: true
            description: ID периода
        responses:
          200:
            description: Период успешно удалён
            schema:
              type: object
              properties:
                message: {type: string}
          404:
            description: Период не найден
        """
    period = Period.query.get_or_404(period_id)
    db.session.delete(period)
    db.session.commit()
    return jsonify({'message': 'Period deleted'})


@main_bp.route('/categories', methods=['GET'])
def get_categories():
    """
        Получить список всех категорий
        ---
        tags:
          - Категории
        summary: Получить список всех категорий
        description: Возвращает массив всех категорий, зарегистрированных в системе.
        responses:
          200:
            description: Список категорий
            schema:
              type: array
              items:
                type: object
                properties:
                  id: {type: integer}
                  name: {type: string}
        """
    categories = Category.query.all()
    return jsonify([{'id': c.id, 'name': c.name} for c in categories])


@main_bp.route('/categories', methods=['POST'])
def create_category():
    """
    Добавить новую категорию
    ---
    tags:
      - Категории
    summary: Добавить новую категорию
    description: Создает новую категорию для классификации экспонатов.
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [name]
          properties:
            name: {type: string, example: "Текстиль"}
    responses:
      201:
        description: Категория успешно создана
        schema:
          type: object
          properties:
            message: {type: string}
            id: {type: integer}
    """
    data = request.json
    category = Category(name=data.get('name'))
    db.session.add(category)
    db.session.commit()
    return jsonify({'message': 'Category created', 'id': category.id}), 201


@main_bp.route('/categories/<int:category_id>', methods=['PUT'])
def update_category(category_id):
    """
        Обновить категорию по id
        ---
        tags:
          - Категории
        summary: Обновить категорию по id
        description: Изменяет данные существующей категории.
        parameters:
          - in: path
            name: category_id
            type: integer
            required: true
            description: ID категории
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                name: {type: string}
        responses:
          200:
            description: Категория успешно обновлена
            schema:
              type: object
              properties:
                message: {type: string}
        """
    category = Category.query.get_or_404(category_id)
    data = request.json
    category.name = data.get('name', category.name)
    db.session.commit()
    return jsonify({'message': 'Category updated'})


@main_bp.route('/categories/<int:category_id>', methods=['DELETE'])
def delete_category(category_id):
    """
        Удалить категорию по id
        ---
        tags:
          - Категории
        summary: Удалить категорию по id
        description: Полностью удаляет категорию из системы по ее идентификатору.
        parameters:
          - in: path
            name: category_id
            type: integer
            required: true
            description: ID категории
        responses:
          200:
            description: Категория успешно удалена
            schema:
              type: object
              properties:
                message: {type: string}
          404:
            description: Категория не найдена
        """
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    return jsonify({'message': 'Category deleted'})


# --- Author CRUD ---

@main_bp.route('/authors', methods=['GET'])
def get_authors():
    """
            Получить список всех авторов
            ---
            tags:
              - Авторы
            summary: Получить список всех авторов
            description: Возвращает массив всех авторов, добавленных в систему.
            responses:
              200:
                description: Список авторов
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      id: {type: integer}
                      full_name: {type: string}
                      birth_date: {type: string}
                      place_of_residence: {type: string}
                      additional_info: {type: string}
            """
    authors = Author.query.all()
    result = []
    for author in authors:
        result.append({
            'id': author.id,
            'full_name': author.full_name,
            'birth_date': author.birth_date,
            'place_of_residence': author.place_of_residence,
            'additional_info': author.additional_info
        })
    return jsonify(result)


@main_bp.route('/authors/<int:author_id>', methods=['GET'])
def get_author(author_id):
    """
            Получить автора по id
            ---
            tags:
              - Авторы
            summary: Получить автора по id
            description: Возвращает информацию об авторе по его идентификатору.
            parameters:
              - in: path
                name: author_id
                type: integer
                required: true
                description: ID автора
            responses:
              200:
                description: Информация об авторе
                schema:
                  type: object
                  properties:
                    id: {type: integer}
                    full_name: {type: string}
                    birth_date: {type: string}
                    place_of_residence: {type: string}
                    additional_info: {type: string}
              404:
                description: Автор не найден
            """
    author = Author.query.get_or_404(author_id)
    return jsonify({
        'id': author.id,
        'full_name': author.full_name,
        'birth_date': author.birth_date,
        'place_of_residence': author.place_of_residence,
        'additional_info': author.additional_info
    })


@main_bp.route('/authors', methods=['POST'])
def create_author():
    """
        Создать нового автора
        ---
        tags:
          - Авторы
        summary: Создать нового автора
        description: Добавляет нового автора в систему.
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [full_name]
              properties:
                full_name: {type: string, example: "Иванова Мария Петровна"}
                birth_date: {type: string, example: "1913-02-20"}
                place_of_residence: {type: string, example: "Томская область"}
                additional_info: {type: string, example: "Занималась вышивкой с детства."}
        responses:
          201:
            description: Автор успешно создан
            schema:
              type: object
              properties:
                message: {type: string}
                id: {type: integer}
        """
    data = request.json
    author = Author(
        full_name=data.get('full_name'),
        birth_date=data.get('birth_date'),
        place_of_residence=data.get('place_of_residence'),
        additional_info=data.get('additional_info')
    )
    db.session.add(author)
    db.session.commit()
    return jsonify({'message': 'Author created', 'id': author.id}), 201


@main_bp.route('/authors/<int:author_id>', methods=['PUT'])
def update_author(author_id):
    """
        Обновить автора по id
        ---
        tags:
          - Авторы
        summary: Обновить автора по id
        description: Изменяет данные существующего автора.
        parameters:
          - in: path
            name: author_id
            type: integer
            required: true
            description: ID автора
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                full_name: {type: string}
                birth_date: {type: string}
                place_of_residence: {type: string}
                additional_info: {type: string}
        responses:
          200:
            description: Автор успешно обновлен
            schema:
              type: object
              properties:
                message: {type: string}
        """
    author = Author.query.get_or_404(author_id)
    data = request.json
    author.full_name = data.get('full_name', author.full_name)
    author.birth_date = data.get('birth_date', author.birth_date)
    author.place_of_residence = data.get('place_of_residence', author.place_of_residence)
    author.additional_info = data.get('additional_info', author.additional_info)
    db.session.commit()
    return jsonify({'message': 'Author updated'})


@main_bp.route('/authors/<int:author_id>', methods=['DELETE'])
def delete_author(author_id):
    """
        Удалить автора по id
        ---
        tags:
          - Авторы
        summary: Удалить автора по id
        description: Полностью удаляет автора из системы по его идентификатору.
        parameters:
          - in: path
            name: author_id
            type: integer
            required: true
            description: ID автора
        responses:
          200:
            description: Автор успешно удалён
            schema:
              type: object
              properties:
                message: {type: string}
          404:
            description: Автор не найден
        """
    author = Author.query.get_or_404(author_id)
    db.session.delete(author)
    db.session.commit()
    return jsonify({'message': 'Author deleted'})


# Получить список всех артефактов
@main_bp.route('/artifacts', methods=['GET'])
def get_artifacts():
    """
    Получить список всех экспонатов с фильтрацией
    ---
    tags:
      - Артефакты
    summary: Получить список всех экспонатов
    description: Фильтрация по категории, периоду, географии, названию, автору, материалу, технике, ключевому слову.
    parameters:
      - in: query
        name: category_id
        type: integer
        description: ID категории
      - in: query
        name: period_id
        type: integer
        description: ID периода
      - in: query
        name: geography_id
        type: integer
        description: ID географии
      - in: query
        name: author_id
        type: integer
        description: ID автора
      - in: query
        name: materials
        type: string
        description: Материал
      - in: query
        name: technique
        type: string
        description: Техника
      - in: query
        name: search
        type: string
        description: Ключевое слово (поиск по названию и описанию)
    responses:
      200:
        description: Список экспонатов
        schema:
          type: array
          items:
            type: object
    """
    query = Artifact.query.filter_by(status='approved')

    # Фильтр по category_id (ID категории)
    category_id = request.args.get('category_id', type=int)
    if category_id:
        query = query.filter(Artifact.category_id == category_id)

    # Фильтр по period_id
    period_id = request.args.get('period_id', type=int)
    if period_id:
        query = query.filter(Artifact.period_id == period_id)

    # Фильтр по geography_id
    geography_id = request.args.get('geography_id', type=int)
    if geography_id:
        query = query.filter(Artifact.geography_id == geography_id)

    # Фильтр по author_id
    author_id = request.args.get('author_id', type=int)
    if author_id:
        query = query.filter(Artifact.author_id == author_id)

    # Фильтр по материалу (подстрочное вхождение)
    materials = request.args.get('materials')
    if materials:
        query = query.filter(Artifact.materials.ilike(f'%{materials}%'))

    # Фильтр по технике (подстрочное вхождение)
    technique = request.args.get('technique')
    if technique:
        query = query.filter(Artifact.technique.ilike(f'%{technique}%'))

    # Поиск по ключевому слову (в названии или описании/истории)
    search = request.args.get('search')
    if search:
        search = f'%{search}%'
        query = query.filter(or_(Artifact.name.ilike(search), Artifact.story.ilike(search)))

    artifacts = query.all()
    result = []
    for artifact in artifacts:
        result.append({
            'id': artifact.id,
            'name': artifact.name,
            'materials': artifact.materials,
            'technique': artifact.technique,
            'creation_date': artifact.creation_date,
            'story': artifact.story,
            'photo_url': artifact.photo_url,
            'applicant_id': artifact.applicant_id,
            'author_id': artifact.author_id,
            'category_id': artifact.category_id,
            'period_id': artifact.period_id,
            'geography_id': artifact.geography_id
        })
    return jsonify(result)


# Получить артефакты
@main_bp.route('/artifacts/<int:artifact_id>', methods=['GET'])
def get_artifact(artifact_id):
    """
        Получить экспонат по id
        ---
        tags:
          - Артефакты
        summary: Получить экспонат по id
        description: Возвращает подробную информацию об экспонате (артефакте) по его идентификатору.
        parameters:
          - in: path
            name: artifact_id
            required: true
            type: integer
            description: ID экспоната
        responses:
          200:
            description: Информация об экспонате
            schema:
              type: object
              properties:
                id:
                  type: integer
                name:
                  type: string
                materials:
                  type: string
                technique:
                  type: string
                creation_date:
                  type: string
                story:
                  type: string
                photo_url:
                  type: string
                applicant_id:
                  type: integer
                author_id:
                  type: integer
                category_id:
                  type: integer
                period_id:
                  type: integer
                geography_id:
                  type: integer
                files:
                  type: array
                  items:
                    type: object
                    properties:
                      id:
                        type: integer
                      file_url:
                        type: string
                      file_type:
                        type: string
          404:
            description: Экспонат не найден
        """
    artifact = Artifact.query.get_or_404(artifact_id)
    files = [
        {
            "id": f.id,
            "file_url": f.file_url,
            "file_type": f.file_type
        }
        for f in artifact.files
    ]
    result = {
        'id': artifact.id,
        'name': artifact.name,
        'materials': artifact.materials,
        'technique': artifact.technique,
        'creation_date': artifact.creation_date,
        'story': artifact.story,
        'photo_url': artifact.photo_url,
        'applicant_id': artifact.applicant_id,
        'author_id': artifact.author_id,
        'category_id': artifact.category_id,
        'period_id': artifact.period_id,
        'geography_id': artifact.geography_id,
        'files': files
    }
    return jsonify(result)


# Добавить новый артефакт
@main_bp.route('/artifacts', methods=['POST'])
def create_artifact():
    """
        Создать новый экспонат
        ---
        tags:
          - Артефакты
        summary: Создать новый экспонат
        description: Добавляет новый экспонат (артефакт) в систему.
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - name
              properties:
                name:
                  type: string
                  example: "Старинная скатерть"
                materials:
                  type: string
                  example: "Хлопок"
                technique:
                  type: string
                  example: "Вышивка"
                creation_date:
                  type: string
                  example: "1967"
                story:
                  type: string
                  example: "Сделана бабушкой в подарок."
                photo_url:
                  type: string
                  example: "https://example.com/photo.jpg"
                applicant_id:
                  type: integer
                author_id:
                  type: integer
                category_id:
                  type: integer
                period_id:
                  type: integer
                geography_id:
                  type: integer
        responses:
          201:
            description: Экспонат успешно создан
            schema:
              type: object
              properties:
                message:
                  type: string
                id:
                  type: integer
        """
    data = request.json
    artifact = Artifact(
        name=data.get('name'),
        materials=data.get('materials'),
        technique=data.get('technique'),
        creation_date=data.get('creation_date'),
        story=data.get('story'),
        photo_url=data.get('photo_url'),
        applicant_id=data.get('applicant_id'),
        author_id=data.get('author_id'),
        category_id=data.get('category_id'),
        period_id=data.get('period_id'),
        geography_id=data.get('geography_id')
    )
    db.session.add(artifact)
    db.session.commit()
    return jsonify({'message': 'Artifact created', 'id': artifact.id}), 201


# Обновить артефакт
@main_bp.route('/artifacts/<int:artifact_id>', methods=['PUT'])
def update_artifact(artifact_id):
    """
        Обновить экспонат по id
        ---
        tags:
          - Артефакты
        summary: Обновить экспонат по id
        description: Изменяет данные существующего экспоната (артефакта).
        parameters:
          - in: path
            name: artifact_id
            required: true
            type: integer
            description: ID экспоната
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                name:
                  type: string
                materials:
                  type: string
                technique:
                  type: string
                creation_date:
                  type: string
                story:
                  type: string
                photo_url:
                  type: string
                applicant_id:
                  type: integer
                author_id:
                  type: integer
                category_id:
                  type: integer
                period_id:
                  type: integer
                geography_id:
                  type: integer
        responses:
          200:
            description: Экспонат успешно обновлен
            schema:
              type: object
              properties:
                message:
                  type: string
        """
    artifact = Artifact.query.get_or_404(artifact_id)
    data = request.json
    artifact.name = data.get('name', artifact.name)
    artifact.materials = data.get('materials', artifact.materials)
    artifact.technique = data.get('technique', artifact.technique)
    artifact.creation_date = data.get('creation_date', artifact.creation_date)
    artifact.story = data.get('story', artifact.story)
    artifact.photo_url = data.get('photo_url', artifact.photo_url)
    artifact.applicant_id = data.get('applicant_id', artifact.applicant_id)
    artifact.author_id = data.get('author_id', artifact.author_id)
    artifact.category_id = data.get('category_id', artifact.category_id)
    artifact.period_id = data.get('period_id', artifact.period_id)
    artifact.geography_id = data.get('geography_id', artifact.geography_id)
    db.session.commit()
    return jsonify({'message': 'Artifact updated'})


# Удалить артефакт
@main_bp.route('/artifacts/<int:artifact_id>', methods=['DELETE'])
def delete_artifact(artifact_id):
    """
        Удалить экспонат по id
        ---
        tags:
          - Артефакты
        summary: Удалить экспонат по id
        description: Полностью удаляет экспонат (артефакт) из системы по его идентификатору.
        parameters:
          - in: path
            name: artifact_id
            required: true
            type: integer
            description: ID экспоната
        responses:
          200:
            description: Экспонат успешно удалён
            schema:
              type: object
              properties:
                message:
                  type: string
          404:
            description: Экспонат не найден
        """
    artifact = Artifact.query.get_or_404(artifact_id)
    db.session.delete(artifact)
    db.session.commit()
    return jsonify({'message': 'Artifact deleted'})
