from functools import wraps

import jwt
from flask import Flask, jsonify, request

from models import Ad, User, db

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:postgres@db:5432/ads"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
SECRET = "change-me-in-production"

db.init_app(app)

def get_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header.split(" ", 1)[1]
    return None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_token()
        if not token:
            return jsonify({"error": "требуется авторизация"}), 401
        try:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "неверный токен"}), 401
        user = db.session.get(User, payload["user_id"])
        if user is None:
            return jsonify({"error": "пользователь не найден"}), 401
        request.current_user = user
        return fn(*args, **kwargs)
    return wrapper


def owner_required(fn):
    @wraps(fn)
    @auth_required
    def wrapper(*args, **kwargs):
        ad_id = kwargs.pop("ad_id")
        ad = db.session.get(Ad, ad_id)
        if ad is None:
            return jsonify({"error": "объявление не найдено"}), 404
        if ad.owner_id != request.current_user.id:
            return jsonify({"error": "нет прав на это объявление"}), 403
        kwargs["ad"] = ad
        return fn(*args, **kwargs)
    return wrapper


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email, password = data.get("email"), data.get("password")
    if not email or not password:
        return jsonify({"error": "нужны email и password"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email уже занят"}), 409
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"id": user.id, "email": user.email}), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    user = User.query.filter_by(email=data.get("email")).first()
    if user is None or not user.check_password(data.get("password", "")):
        return jsonify({"error": "неверный email или пароль"}), 401
    token = jwt.encode({"user_id": user.id}, SECRET, algorithm="HS256")
    return jsonify({"token": token})

@app.post("/ads")
@auth_required
def create_ad():
    data = request.get_json(silent=True) or {}
    title, description = data.get("title"), data.get("description")
    if not title or not description:
        return jsonify({"error": "нужны title и description"}), 400
    ad = Ad(title=title, description=description,
            owner_id=request.current_user.id)
    db.session.add(ad)
    db.session.commit()
    return jsonify(ad.to_dict()), 201


@app.get("/ads/<int:ad_id>")
def get_ad(ad_id: int):
    ad = db.session.get(Ad, ad_id)
    if ad is None:
        return jsonify({"error": "объявление не найдено"}), 404
    return jsonify(ad.to_dict())


@app.patch("/ads/<int:ad_id>")
@owner_required
def update_ad(ad: Ad):
    data = request.get_json(silent=True) or {}
    if "title" in data:
        ad.title = data["title"]
    if "description" in data:
        ad.description = data["description"]
    db.session.commit()
    return jsonify(ad.to_dict())


@app.delete("/ads/<int:ad_id>")
@owner_required
def delete_ad(ad: Ad):
    db.session.delete(ad)
    db.session.commit()
    return jsonify({"status": "deleted"})


@app.get("/ads")
def list_ads():
    ads = Ad.query.order_by(Ad.created_at.desc()).all()
    return jsonify([ad.to_dict() for ad in ads])


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)