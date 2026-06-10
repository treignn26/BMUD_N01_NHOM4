from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import url_for
from flask import session
from flask_bcrypt import Bcrypt
from models import db
from models import User
from models import PasswordEntry
from security import encrypt_password
from security import decrypt_password
from security import check_password_strength
import random
import string
from models import ActivityLog
import csv
from io import StringIO
from flask import Response
from flask import flash
from datetime import datetime, timedelta
app = Flask(__name__)

app.config["SECRET_KEY"] = "passwordmanager"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///password_manager.db"

db.init_app(app)

bcrypt = Bcrypt(app)

def write_log(user_id, action):

    log = ActivityLog(
        user_id=user_id,
        action=action
    )

    db.session.add(log)
    db.session.commit()

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Kiểm tra email đã tồn tại chưa
        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:
            return "Email đã tồn tại"

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        user = User(
            username=username,
            email=email,
            password_hash=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(
            username=username
        ).first()
        if user and user.locked_until:

            if user.locked_until > datetime.utcnow():

                return """
                Tài khoản đã bị khóa do nhập sai quá nhiều lần.
                Vui lòng thử lại sau 5 phút.
                """
        if user and bcrypt.check_password_hash(
            user.password_hash,
            password
        ):
            user.failed_attempts = 0
            user.locked_until = None

            db.session.commit()

            session["user_id"] = user.id
            session["username"] = user.username
            write_log(
                user.id,
                "Login"
            )
            return redirect(url_for("dashboard"))

        if user:

            user.failed_attempts += 1

            if user.failed_attempts >= 5:

                user.locked_until = (
                    datetime.utcnow()
                    + timedelta(minutes=5)
                )

                user.failed_attempts = 0

            db.session.commit()

        return "Sai tài khoản hoặc mật khẩu"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    keyword = request.args.get("keyword")

    query = PasswordEntry.query.filter_by(
        user_id=session["user_id"]
    )

    if keyword:
        query = query.filter(
            PasswordEntry.website.ilike(
                f"%{keyword}%"
            )
        )

    passwords = query.all()
    total_passwords = len(passwords)

    return render_template(
        "dashboard.html",
        username=session["username"],
        passwords=passwords,
        total_passwords=total_passwords   
    )

@app.route("/add_password", methods=["GET", "POST"])
def add_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    strength = None

    if request.method == "POST":

        website = request.form["website"]
        account_username = request.form["account_username"]
        password = request.form["password"]

        strength = check_password_strength(
            password
        )

        encrypted = encrypt_password(password)

        entry = PasswordEntry(
            website=website,
            account_username=account_username,
            encrypted_password=encrypted,
            user_id=session["user_id"]
        )

        db.session.add(entry)
        db.session.commit()

        write_log(
            session["user_id"],
            "Add Password"
        )

        flash(
            f"Đã lưu mật khẩu thành công! Độ mạnh: {strength}",
            "success"
        )
        return redirect(url_for("dashboard"))

    return render_template(
        "add_password.html",
        strength=strength
    )

@app.route("/generate_password")
def generate_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()"
    )

    password = "".join(
        random.choice(characters)
        for _ in range(16)
    )

    return render_template(
        "generated_password.html",
        password=password
    )

@app.route("/view_password/<int:id>")
def view_password(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    entry = PasswordEntry.query.get_or_404(id)

    if entry.user_id != session["user_id"]:
        return "Không có quyền truy cập"

    decrypted = decrypt_password(
        entry.encrypted_password
    )
    return render_template(
        "view_password.html",
        entry=entry,
        password=decrypted
    )

@app.route("/edit_password/<int:id>", methods=["GET", "POST"])
def edit_password(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    entry = PasswordEntry.query.get_or_404(id)

    if entry.user_id != session["user_id"]:
        return "Không có quyền truy cập"

    if request.method == "POST":

        entry.website = request.form["website"]

        entry.account_username = request.form[
            "account_username"
        ]

        new_password = request.form["password"]

        entry.encrypted_password = encrypt_password(
            new_password
        )

        db.session.commit()
        write_log(
            session["user_id"],
            "Edit Password"
        )
        return redirect(url_for("dashboard"))

    return render_template(
        "edit_password.html",
        entry=entry
    )

@app.route("/delete_password/<int:id>")
def delete_password(id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    entry = PasswordEntry.query.get_or_404(id)

    if entry.user_id != session["user_id"]:
        return "Không có quyền truy cập"

    db.session.delete(entry)
    db.session.commit()
    write_log(
        session["user_id"],
        "Delete Password"
    )
    return redirect(url_for("dashboard"))

@app.route("/logs")
def logs():

    if "user_id" not in session:
        return redirect(url_for("login"))

    logs = ActivityLog.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        ActivityLog.created_at.desc()
    ).all()

    return render_template(
        "logs.html",
        logs=logs
    )

@app.route("/export_csv")
def export_csv():

    if "user_id" not in session:
        return redirect(url_for("login"))

    passwords = PasswordEntry.query.filter_by(
        user_id=session["user_id"]
    ).all()

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Website",
        "Username"
    ])

    for p in passwords:

        writer.writerow([
            p.website,
            p.account_username
        ])

    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )

    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=passwords.csv"

    return response

@app.route("/change_password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        old_password = request.form["old_password"]
        new_password = request.form["new_password"]

        user = User.query.get(
            session["user_id"]
        )

        if not bcrypt.check_password_hash(
            user.password_hash,
            old_password
        ):
            return "Mật khẩu cũ không đúng"

        user.password_hash = bcrypt.generate_password_hash(
            new_password
        ).decode("utf-8")

        db.session.commit()

        write_log(
            session["user_id"],
            "Change Account Password"
        )

        return redirect(url_for("dashboard"))

    return render_template(
        "change_password.html"
    )

@app.route("/logout")
def logout():

    if "user_id" in session:

        write_log(
            session["user_id"],
            "Logout"
        )
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)