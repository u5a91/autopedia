import os
from dotenv import load_dotenv

import bleach
from datetime import datetime, timezone

from markdown import markdown

from flask import (
    Flask, render_template, redirect,
    url_for, request, flash, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_migrate import Migrate   # DB の差分管理

from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash

from openai import OpenAI

# UTC
def utcnow():
    return datetime.now(timezone.utc)

# Markdown -> HTML のサニタイジング
ALLOWED_TAGS = bleach.sanitizer.ALLOWED_TAGS.union({
    "p","br","pre","code","blockquote",
    "ul","ol","li",
    "strong","em","del",
    "h1","h2","h3","h4",
    "table","thead","tbody","tr","th","td","a",
    "div", "span", "img"
})
ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"],
    "code": ["class"],
    "span": ["class"],
    "pre": ["class"],
    "div": ["class"], 
    "img": ["src", "alt", "title", "width"]
}
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]

def sanitize_html(html: str) -> str:
    cleaned = bleach.clean(
        html,
        tags=list(ALLOWED_TAGS),
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,     # 許可されていない HTML タグは完全に削除
    )
    cleaned = bleach.linkify(cleaned)
    return cleaned

# App
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///autopedia.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False    # オブジェクトの変更履歴を逐次追跡しない

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"  # エンドポイント名

# OpenAI Python クライアント初期化
openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Model (= Entity) 定義
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    # User, Entry の 1:N. 遅延ロード
    entries = db.relationship("Entry", backref="author", lazy=True)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str):
        return check_password_hash(self.password_hash, password)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)

    content = db.Column(db.Text, nullable=True)
    context = db.Column(db.Text, nullable=True)     # 説明文脈
    tags = db.Column(db.String(400), nullable=True)     # 今は "文学, 宗教, 思想"みたいにして, list 的な正規化はまだ

    model = db.Column(db.String(80), nullable=True)
    prompt_version = db.Column(db.String(40), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)      # INSERT 時値セット
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)     # 加えて UPDATE 時値セット
    
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# Auth
@login_manager.user_loader
def log_user(user_id):
    return User.query.get(int(user_id))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("ユーザ名とパスワードを入力してください. ")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("そのユーザ名はすでに使われています. ")
            return redirect(url_for("register"))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("登録が完了しました. ログインしてください. ")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("entries"))

        flash("ユーザ名またはパスワードが違います. ")    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# Pages
@app.route("/")
@login_required
def entries():
    q = (request.args.get("q") or "").strip()   # 検索窓, 前後の空白削除

    query = Entry.query.filter(Entry.user_id == current_user.id)
    if q:
        like = f"%{q}%"
        # 全文検索
        query = query.filter(
            or_(
                Entry.title.ilike(like),
                Entry.content.ilike(like),
                Entry.context.ilike(like),
                Entry.tags.ilike(like),
            )
        )

    items = query.order_by(Entry.updated_at.desc()).all()
    return render_template("entries.html", items=items, q=q)

@app.route("/entry/<int:entry_id>")
@login_required
def entry_view(entry_id: int):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)
    
    raw_html = markdown(
        entry.content or "",
        extensions=["fenced_code", "tables", "sane_lists"],
    )
    content_html = sanitize_html(raw_html)

    tag_list = []
    if entry.tags:
        tag_list = [t.strip() for t in entry.tags.split(",") if t.strip()]

    return render_template(
        "entry_view.html",
        entry=entry,
        content_html=content_html,
        tag_list=tag_list,
    )

@app.route("/new", methods=["GET", "POST"])
@login_required
def new_entry():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        content = (request.form.get("content") or "").strip()
        context = (request.form.get("context") or "").strip() or None
        tags = (request.form.get("tags") or "").strip() or None

        if not title or not content:
            flash("タイトルは必須です. ")
            return redirect(url_for("new_entry"))

        entry = Entry(
            title=title,
            content=content,
            context=context,
            tags=tags,
            model="manual",
            prompt_version="manual",
            author=current_user
        )

        db.session.add(entry)
        db.session.commit()
        return redirect(url_for("entry_view", entry_id=entry.id))

    return render_template("new_entry.html")

@app.route("/entry/<int:entry_id>/edit", methods=["GET", "POST"])
@login_required
def edit_entry(entry_id: int):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)

    if request.method == "POST":
        entry.title = (request.form.get("title") or "").strip()
        entry.content = (request.form.get("content") or "").strip()
        entry.context = (request.form.get("context") or "").strip() or None
        entry.tags = (request.form.get("tags") or "").strip() or None

        if not entry.title or not entry.content:
            flash("タイトルは必須です. ")
            return redirect(url_for("edit_entry", entry_id=entry.id))

        db.session.commit()
        return redirect(url_for("entry_view", entry_id=entry.id))

    return render_template("edit_entry.html", entry=entry)

@app.route("/delete/<int:entry_id>", methods=["POST"])
@login_required
def delete_entry(entry_id: int):
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        abort(403)

    db.session.delete(entry)
    db.session.commit()
    flash("削除しました. ")
    return redirect(url_for("entries"))

# LLM API
AUTOPEDIA_PROMPT_VERSION = "v1"
AUTOPEDIA_MODEL = os.getenv("AUTOPEDIA_MODEL", "gpt-5.2")

SYSTEM_INSTRUCTIONS = """
あなたは辞書の書き手です. 
以下の条件を必ず守ってください: 
- 出力は必ず Markdown
"""

def build_user_input(
    title: str, 
    context: str | None,
    tags: str | None
    ) -> str:
    parts = [f"見出し語: {title}"]
    if context:
        parts.append(f"遭遇した文脈: \n{context}")
    if tags:
        parts.append(f"想定タグ: {tags}")
    parts.append("この見出し語について説明を書いてください. ")
    return "\n\n".join(parts)

@app.route("/generate", methods=["GET", "POST"])
@login_required
def generate():
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        context = (request.form.get("context") or "").strip() or None
        tags = (request.form.get("tags") or "").strip() or None

        if not title:
            flash("タイトルは必須です. ")
            return redirect(url_for("generate"))

        user_input = build_user_input(title=title, context=context, tags=tags)

        try:
            resp = openai_client.responses.create(
                model=AUTOPEDIA_MODEL,
                instructions=SYSTEM_INSTRUCTIONS,
                input=user_input,
            )
            content_md = (resp.output_text or "").strip()
        except Exception as e:
            flash(f"OpenAI API 呼び出しに失敗しました: {e}")
            return redirect(url_for("generate"))

        if not content_md:
            flash("LLM から空の出力が返りました. もう一度試してみてください. ")
            return redirect(url_for("generate"))

        entry = Entry(
            title=title,
            content=content_md,
            context=context,
            tags=tags,
            model=AUTOPEDIA_MODEL,
            prompt_version=AUTOPEDIA_PROMPT_VERSION,
            author=current_user,
        )
        db.session.add(entry)
        db.session.commit()

        return redirect(url_for("entry_view", entry_id=entry.id))

    return render_template("generate.html")

# Markdown preview
@app.route("/markdown_preview", methods=["POST"])
@login_required
def markdown_preview():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "") or ""

    raw_html = markdown(
        text,
        extensions=["fenced_code", "tables", "sane_lists"],
    )
    html = sanitize_html(raw_html)
    return jsonify({"html": html})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)