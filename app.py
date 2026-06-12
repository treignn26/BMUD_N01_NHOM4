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
from security import generate_kdf_salt
from security import derive_vault_key
import os
import random
import string
from models import ActivityLog
import csv
from io import StringIO
from flask import Response
from flask import flash
from datetime import datetime, timedelta
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    os.urandom(32).hex()
)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///password_manager.db"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=15
)

db.init_app(app)

bcrypt = Bcrypt(app)

VAULT_UNLOCK_MINUTES = 3


def is_vault_unlocked():
    unlocked_until = session.get("vault_unlocked_until")

    if not unlocked_until:
        return False

    return datetime.fromisoformat(unlocked_until) > datetime.utcnow()


def is_safe_next_url(target):
    return (
        bool(target)
        and target.startswith("/")
        and not target.startswith("//")
    )


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
            flash("Email đã tồn tại", "danger")
            return render_template("register.html")

        if check_password_strength(password) == "Yếu":
            flash(
                "Mật khẩu quá yếu. Hãy dùng ít nhất 8 ký tự, "
                "gồm chữ hoa, chữ thường, số và ký tự đặc biệt.",
                "danger"
            )
            return render_template("register.html")

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            kdf_salt=generate_kdf_salt()
        )

        db.session.add(user)
        db.session.commit()

        flash(
            "Đăng ký thành công! Vui lòng đăng nhập để tiếp tục.",
            "success"
        )
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    next_url = request.values.get("next", "")

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(
            username=username
        ).first()
        if user and user.locked_until:

            if user.locked_until > datetime.utcnow():
                if user:
                    write_log(
                        user.id,
                        "Failed Login"
                    )               
                flash(
                    "Tài khoản đã bị khóa do nhập sai quá nhiều lần. "
                    "Vui lòng thử lại sau 5 phút.",
                    "danger"
                )
                return render_template(
                    "login.html",
                    next=next_url,
                    locked=True
                )
        if user and bcrypt.check_password_hash(
            user.password_hash,
            password
        ):
            user.failed_attempts = 0
            user.locked_until = None

            db.session.commit()

            session.permanent = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["vault_key"] = derive_vault_key(
                password,
                user.kdf_salt
            )
            write_log(
                user.id,
                "Login"
            )

            if is_safe_next_url(next_url):
                return redirect(next_url)

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

        flash("Sai tài khoản hoặc mật khẩu", "danger")
        return render_template("login.html", next=next_url)

    return render_template("login.html", next=next_url)


@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login", next=request.path))

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
        return redirect(url_for("login", next=request.path))

    strength = None

    if request.method == "POST":

        website = request.form["website"]
        account_username = request.form["account_username"]
        password = request.form["password"]

        strength = check_password_strength(
            password
        )

        encrypted = encrypt_password(
            password,
            session["vault_key"]
        )

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
            f"Add Password ({website})"
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
        return redirect(url_for("login", next=request.path))

    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()"
    )

    password = "".join(
        random.choice(characters)
        for _ in range(16)
    )

    write_log(
        session["user_id"],
        "Generate Password"
    )

    return render_template(
        "generated_password.html",
        password=password
    )

@app.route("/view_password/<int:id>", methods=["GET", "POST"])
def view_password(id):

    if "user_id" not in session:
        return redirect(url_for("login", next=request.path))

    entry = PasswordEntry.query.get_or_404(id)

    if entry.user_id != session["user_id"]:
        return "Không có quyền truy cập"

    if request.method == "POST":

        user = User.query.get(session["user_id"])

        if user.locked_until and user.locked_until > datetime.utcnow():
            flash(
                "Tài khoản đã bị khóa do nhập sai quá nhiều lần. "
                "Vui lòng thử lại sau 5 phút.",
                "danger"
            )
            return render_template(
                "confirm_password.html",
                entry=entry,
                locked=True
            )

        if bcrypt.check_password_hash(
            user.password_hash,
            request.form["confirm_password"]
        ):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            session["vault_unlocked_until"] = (
                datetime.utcnow()
                + timedelta(minutes=VAULT_UNLOCK_MINUTES)
            ).isoformat()
        else:
            user.failed_attempts += 1

            if user.failed_attempts >= 5:
                user.locked_until = (
                    datetime.utcnow()
                    + timedelta(minutes=5)
                )
                user.failed_attempts = 0

            db.session.commit()

            flash("Mật khẩu không đúng", "danger")
            return render_template(
                "confirm_password.html",
                entry=entry,
                locked=bool(user.locked_until)
            )

    if not is_vault_unlocked():

        user = User.query.get(session["user_id"])

        is_locked = bool(
            user.locked_until
            and user.locked_until > datetime.utcnow()
        )

        if is_locked:
            flash(
                "Tài khoản đã bị khóa do nhập sai quá nhiều lần. "
                "Vui lòng thử lại sau 5 phút.",
                "danger"
            )

        return render_template(
            "confirm_password.html",
            entry=entry,
            locked=is_locked
        )

    decrypted = decrypt_password(
        entry.encrypted_password,
        session["vault_key"]
    )

    write_log(
        session["user_id"],
        f"View Password ({entry.website})"
    )

    return render_template(
        "view_password.html",
        entry=entry,
        password=decrypted
    )

@app.route("/edit_password/<int:id>", methods=["GET", "POST"])
def edit_password(id):

    if "user_id" not in session:
        return redirect(url_for("login", next=request.path))

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
            new_password,
            session["vault_key"]
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
        return redirect(url_for("login", next=request.path))

    entry = PasswordEntry.query.get_or_404(id)

    if entry.user_id != session["user_id"]:
        return "Không có quyền truy cập"

    db.session.delete(entry)
    db.session.commit()
    write_log(
        session["user_id"],
        f"Delete Password ({entry.website})"
    )
    return redirect(url_for("dashboard"))

@app.route("/logs")
def logs():

    if "user_id" not in session:
        return redirect(url_for("login", next=request.path))

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
        return redirect(url_for("login", next=request.path))

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
    
    write_log(
        session["user_id"],
        "Export CSV"
    )

    return response

@app.route("/change_password", methods=["GET", "POST"])
def change_password():

    if "user_id" not in session:
        return redirect(url_for("login", next=request.path))

    if request.method == "POST":

        old_password = request.form["old_password"]
        new_password = request.form["new_password"]
        confirm_new_password = request.form["confirm_new_password"]

        user = User.query.get(
            session["user_id"]
        )

        if not bcrypt.check_password_hash(
            user.password_hash,
            old_password
        ):
            flash("Mật khẩu cũ không đúng", "danger")
            return render_template("change_password.html")

        if new_password != confirm_new_password:
            flash("Mật khẩu mới nhập lại không khớp", "danger")
            return render_template("change_password.html")

        if check_password_strength(new_password) == "Yếu":
            flash(
                "Mật khẩu mới quá yếu. Hãy dùng ít nhất 8 ký tự, "
                "gồm chữ hoa, chữ thường, số và ký tự đặc biệt.",
                "danger"
            )
            return render_template("change_password.html")

        old_vault_key = derive_vault_key(
            old_password,
            user.kdf_salt
        )

        new_salt = generate_kdf_salt()
        new_vault_key = derive_vault_key(
            new_password,
            new_salt
        )

        entries = PasswordEntry.query.filter_by(
            user_id=user.id
        ).all()

        for entry in entries:
            plain = decrypt_password(
                entry.encrypted_password,
                old_vault_key
            )
            entry.encrypted_password = encrypt_password(
                plain,
                new_vault_key
            )

        user.password_hash = bcrypt.generate_password_hash(
            new_password
        ).decode("utf-8")
        user.kdf_salt = new_salt

        db.session.commit()

        session["vault_key"] = new_vault_key

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