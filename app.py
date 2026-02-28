import os
import threading
import random
import json
import re
import io
import zipfile
import mimetypes
import time
import pickle
import uuid
from datetime import datetime, timedelta, timezone
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for, send_from_directory, send_file, abort, make_response
from flask_login import LoginManager, login_user, login_required, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from urllib.parse import unquote
import shutil
from PIL import Image
from flask_login import logout_user # Add this to your imports
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user

SETTINGS_DIR = "settings"
os.makedirs(SETTINGS_DIR, exist_ok=True)
os.makedirs(os.path.join("static", "profile_pics"), exist_ok=True)

db = SQL("sqlite:///logins.db")

app = Flask(__name__)
app.secret_key = "REPLACE_THIS_WITH_A_LONG_RANDOM_SECRET_KEY_12345"  # Change this!

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    # Ensure user_id is treated as an int if your DB uses int IDs
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user:
        return None  # This is crucial!
    
    u = User()
    u.id = user[0]['id']
    u.username = user[0]['username']
    u.emoji = user[0]['emoji']
    return u

@app.context_processor
def inject_settings():
    if current_user.is_authenticated:
        return dict(settings=load_user_settings(current_user.id))
    return dict(settings=None)

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    ...
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# --- AUTH ---

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        emoji = request.form.get('emoji')
        if not username or not password:
            return render_template("error.html", message="Please fill in all fields.")
        if password != confirmation:
            return render_template("error.html", message="Passwords do not match.")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return render_template("error.html", message="Username already taken.")
        hashed = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash, emoji) VALUES (?, ?, ?)", username, hashed, emoji)
        u = User()
        u.id = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
        u.username = username
        u.emoji = emoji
        login_user(u, remember=True)
        return redirect("/")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("error.html", message="Must provide username")
        if not request.form.get("password"):
            return render_template("error.html", message="Must provide password")
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html", message="Invalid username or password")
        u = User()
        u.id = rows[0]["id"]
        u.username = rows[0]["username"]
        u.emoji = rows[0]["emoji"]
        login_user(u, remember=True)
        return redirect("/")
    return render_template("login.html")


# Make sure logout_user is imported at the top!
from flask_login import logout_user 

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    resp = redirect("/")
    resp.delete_cookie("remember_token")
    return resp

@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("index.html")
    return render_template("home1.html")

# --- GENERATE ---

@app.route("/generate", methods=['GET', 'POST'])
@login_required
def generate():
    if request.method == 'POST':
        while True:
            h = random.randint(1000, 10000000)
            if not db.execute("SELECT * FROM group_chats WHERE id = ?", h):
                break
        db.execute("INSERT INTO group_chats (id, custom) VALUES (?, 0)", h)
        return render_template("generate.html", key=h)
    return render_template("generate.html")

# --- CHAT ---

@app.route("/messages/<key>")
@login_required
def get_messages(key):
    try:
        with open("messages.json", "r") as f:
            data = json.load(f)
        return jsonify({"messages": data.get(str(key), [])})
    except Exception as e:
        return render_template("error2.html", message=f"error: {str(e)}")

def extract_mentions(text):
    return set(re.findall(r'@(\w+|everyone)', text or ""))

@app.route("/chat_room/<key>", methods=['POST'])
@login_required
def post_message(key):
    message = request.json.get('message', '')
    image_url = request.json.get('image_url', None)
    reply_to = request.json.get('reply_to', None)
    if not message and not image_url:
        return jsonify({"error": "Message cannot be empty."}), 400
    try:
        with open("messages.json", "r") as f:
            data = json.load(f)
        if str(key) not in data:
            data[str(key)] = []
        user_settings = load_user_settings(current_user.id)
        profile_pic = user_settings.get("profile_pic") or "default.png"
        msg_id = str(uuid.uuid4())
        mentions = extract_mentions(message)
        mentioned_users = []
        highlight = False
        if "everyone" in mentions:
            highlight = True
            mentioned_users = [u['username'] for u in db.execute("SELECT username FROM users")]
        else:
            for username in mentions:
                if username == current_user.username:
                    continue
                rows = db.execute("SELECT * FROM users WHERE username = ?", username)
                if rows:
                    mentioned_users.append(username)
                    highlight = True
        msg_data = {
            "id": msg_id,
            "username": current_user.username,
            "emoji": current_user.emoji,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "profile_pic": profile_pic,
            "highlight": highlight,
            "mentions": mentioned_users,
        }
        if message:
            msg_data["message"] = message
        if image_url:
            msg_data["image_url"] = image_url
        if reply_to:
            msg_data["reply_to"] = reply_to
        data[str(key)].append(msg_data)
        with open("messages.json", "w") as f:
            json.dump(data, f)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_message/<key>/<msg_id>", methods=['POST'])
@login_required
def delete_message(key, msg_id):
    try:
        with open("messages.json", "r") as f:
            data = json.load(f)
        key = str(key)
        if key in data:
            data[key] = [m for m in data[key] if not (m.get("id") == msg_id and m.get("username") == current_user.username)]
        with open("messages.json", "w") as f:
            json.dump(data, f)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/chat", methods=['GET', 'POST'])
@login_required
def chat():
    timeout_until = timeouts.get(current_user.username)
    if timeout_until and datetime.now() < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return render_template("timeout.html", timeout_until=timeout_until)

    # Get groups the user has participated in
    recent_groups = []
    try:
        with open("messages.json", "r") as f:
            data = json.load(f)
        for group_id, messages in data.items():
            for msg in messages:
                if msg.get("username") == current_user.username:
                    recent_groups.append(group_id)
                    break
    except Exception:
        pass

    if request.method == "POST":
        key = request.form.get("key")
        chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", key)
        if len(chat_group) == 0:
            return render_template("chat.html", error="Invalid key. Please try again.", recent_groups=recent_groups)
        return render_template("chat_room.html", key=key)

    return render_template("chat.html", recent_groups=recent_groups)

@app.route("/chat_room/<key>", methods=['GET'])
@login_required
def chat_room_get(key):
    """Allow direct navigation to a chat room (e.g., from generate page or admin Join button)."""
    chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", str(key))
    if not chat_group:
        return render_template("error2.html", message="Invalid group code.")
    return render_template("chat_room.html", key=key)

# --- GET USERS (for DM forward modal) ---
@app.route("/get_users")
@login_required
def get_users():
    users = db.execute("SELECT username FROM users")
    return jsonify({"users": [u['username'] for u in users]})

# --- DIRECT MESSAGES ---

DM_FILE = "dms.json"

def load_dms():
    if not os.path.exists(DM_FILE):
        return {}
    with open(DM_FILE, "r") as f:
        return json.load(f)

def save_dms(data):
    with open(DM_FILE, "w") as f:
        json.dump(data, f)

def get_dm_key(user1, user2):
    """Consistent key for a DM conversation regardless of order."""
    return "__dm__" + "__".join(sorted([user1, user2]))

@app.route("/dm")
@login_required
def dm_list():
    data = load_dms()
    conversations = []
    prefix = "__dm__"
    for convo_key, messages in data.items():
        if not convo_key.startswith(prefix):
            continue
        users = convo_key[len(prefix):].split("__")
        if current_user.username not in users:
            continue
        other = [u for u in users if u != current_user.username]
        if not other:
            continue
        other_username = other[0]
        other_user_row = db.execute("SELECT id FROM users WHERE username = ?", other_username)
        profile_pic = "default.png"
        if other_user_row:
            s = load_user_settings(other_user_row[0]["id"])
            profile_pic = s.get("profile_pic") or "default.png"
        conversations.append({
            "username": other_username,
            "profile_pic": profile_pic,
            "unread": 0
        })
    return render_template("dm.html", conversations=conversations, active_user=None, active_profile_pic="default.png")

@app.route("/dm/<username>")
@login_required
def dm_chat(username):
    # Check user exists
    user_row = db.execute("SELECT * FROM users WHERE username = ?", username)
    if not user_row and username != current_user.username:
        return render_template("error2.html", message="User not found.")
    data = load_dms()
    conversations = []
    prefix = "__dm__"
    for convo_key, messages in data.items():
        if not convo_key.startswith(prefix):
            continue
        users = convo_key[len(prefix):].split("__")
        if current_user.username not in users:
            continue
        other = [u for u in users if u != current_user.username]
        if not other:
            continue
        other_username = other[0]
        other_user_row = db.execute("SELECT id FROM users WHERE username = ?", other_username)
        profile_pic = "default.png"
        if other_user_row:
            s = load_user_settings(other_user_row[0]["id"])
            profile_pic = s.get("profile_pic") or "default.png"
        conversations.append({"username": other_username, "profile_pic": profile_pic, "unread": 0})

    # Also include current user if not already in conversations
    if not any(c["username"] == username for c in conversations) and username != current_user.username:
        row = db.execute("SELECT id FROM users WHERE username = ?", username)
        pp = "default.png"
        if row:
            s = load_user_settings(row[0]["id"])
            pp = s.get("profile_pic") or "default.png"
        conversations.insert(0, {"username": username, "profile_pic": pp, "unread": 0})

    # Active user profile pic
    active_pp = "default.png"
    row = db.execute("SELECT id FROM users WHERE username = ?", username)
    if row:
        s = load_user_settings(row[0]["id"])
        active_pp = s.get("profile_pic") or "default.png"

    return render_template("dm.html", conversations=conversations, active_user=username, active_profile_pic=active_pp)

@app.route("/dm_messages/<username>")
@login_required
def dm_messages(username):
    data = load_dms()
    key = get_dm_key(current_user.username, username)
    return jsonify({"messages": data.get(key, [])})

@app.route("/send_dm", methods=['POST'])
@login_required
def send_dm():
    body = request.json
    to_user = body.get('to')
    message = body.get('message', '')
    image_url = body.get('image_url', None)
    reply_to = body.get('reply_to', None)
    if not to_user:
        return jsonify({"error": "No recipient specified"}), 400
    if not message and not image_url:
        return jsonify({"error": "Empty message"}), 400
    # Check user exists
    user_row = db.execute("SELECT id FROM users WHERE username = ?", to_user)
    if not user_row:
        return jsonify({"error": "User not found"}), 404

    user_settings = load_user_settings(current_user.id)
    profile_pic = user_settings.get("profile_pic") or "default.png"
    msg_id = str(uuid.uuid4())
    msg_data = {
        "id": msg_id,
        "username": current_user.username,
        "emoji": current_user.emoji,
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        "profile_pic": profile_pic,
    }
    if message:
        msg_data["message"] = message
    if image_url:
        msg_data["image_url"] = image_url
    if reply_to:
        msg_data["reply_to"] = reply_to

    data = load_dms()
    key = get_dm_key(current_user.username, to_user)
    if key not in data:
        data[key] = []
    data[key].append(msg_data)
    save_dms(data)
    return jsonify({"success": True}), 200

@app.route("/delete_dm/<msg_id>", methods=['POST'])
@login_required
def delete_dm(msg_id):
    data = load_dms()
    for key in data:
        data[key] = [m for m in data[key] if not (m.get("id") == msg_id and m.get("username") == current_user.username)]
    save_dms(data)
    return jsonify({"success": True}), 200

@app.route("/admin_reset_dms", methods=['POST'])
@login_required
def admin_reset_dms():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    save_dms({})
    return jsonify({"success": True})

# --- CUSTOM GROUP CODE (Admin only) ---

@app.route("/create_custom_group", methods=['POST'])
@login_required
def create_custom_group():
    if current_user.username != "h":
        return jsonify({"error": "Admin privileges required."}), 403
    code = request.json.get('code', '').strip()
    if not code or len(code) < 2:
        return jsonify({"error": "Code must be at least 2 characters."}), 400
    if len(code) > 50:
        return jsonify({"error": "Code must be under 50 characters."}), 400
    existing = db.execute("SELECT * FROM group_chats WHERE id = ?", code)
    if existing:
        return jsonify({"error": f"Group '{code}' already exists."}), 409
    db.execute("INSERT INTO group_chats (id, custom) VALUES (?, 1)", code)
    return jsonify({"success": True, "code": code})

# --- ADMIN ---

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    db.execute("DELETE FROM users WHERE id = ?", current_user.id)
    session.clear()
    flash("Your account has been deleted.")
    return redirect("/")

@app.route("/delete_chat/<chat_id>", methods=["POST"])
@login_required
def delete_chat(chat_id):
    if current_user.username != "h":
        return render_template("error2.html", message="Access denied.")
    db.execute("DELETE FROM group_chats WHERE id = ?", chat_id)
    flash(f"Group chat '{chat_id}' deleted.")
    return redirect("/admin")

def get_directory_size(path):
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total

@app.route("/admin")
@login_required
def admin():
    if current_user.username != "h":
        return render_template("error2.html", message="Access denied: Admin privileges required.")
    users = db.execute("SELECT username, hash FROM users")
    group_chats = db.execute("SELECT id, custom FROM group_chats")
    images_base = os.path.join(os.getcwd(), "IMAGES")
    image_folders = {}
    if os.path.isdir(images_base):
        for key in os.listdir(images_base):
            folder_path = os.path.join(images_base, key)
            if os.path.isdir(folder_path):
                files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
                image_folders[key] = files
    base_dir = os.path.dirname(os.path.abspath(__file__))
    root_size = get_directory_size(base_dir)
    root_size_gb = root_size / (1024 ** 3)
    percent_used = min(100, root_size_gb * 100)

    # DM stats
    dm_stats = None
    try:
        dms = load_dms()
        total_dm_msgs = sum(len(v) for v in dms.values())
        dm_stats = {"total": total_dm_msgs, "conversations": len(dms)}
    except Exception:
        pass

    return render_template("admin.html",
        users=users, group_chats=group_chats, image_folders=image_folders,
        root_size=root_size, root_size_gb=root_size_gb, percent_used=percent_used,
        dm_stats=dm_stats)

@app.route('/delete_images_folder/<key>', methods=['POST'])
@login_required
def delete_images_folder(key):
    if current_user.username != "h":
        return render_template("error2.html", message="Access denied.")
    target = os.path.join(os.getcwd(), "IMAGES", key)
    if os.path.isdir(target):
        shutil.rmtree(target)
    return redirect(url_for('admin'))

@app.route('/delete_images_folders', methods=['POST'])
@login_required
def delete_images_folders():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    keys = request.get_json().get('keys', [])
    images_base = os.path.join(os.getcwd(), "IMAGES")
    for key in keys:
        folder = os.path.join(images_base, key)
        if os.path.isdir(folder):
            shutil.rmtree(folder)
    return jsonify(success=True)

@app.route('/delete_image/<key>/<path:filename>', methods=['POST'])
@login_required
def delete_image(key, filename):
    if current_user.username != "h":
        return render_template("error2.html", message="Access denied.")
    file_path = os.path.join(os.getcwd(), "IMAGES", key, unquote(filename))
    if os.path.isfile(file_path):
        os.remove(file_path)
    return redirect(url_for('admin'))

@app.route('/delete_images', methods=['POST'])
@login_required
def delete_images():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    images = request.get_json().get('images', [])
    images_base = os.path.join(os.getcwd(), "IMAGES")
    for img in images:
        file_path = os.path.join(images_base, img.get('key'), img.get('image'))
        if os.path.isfile(file_path):
            os.remove(file_path)
    return jsonify(success=True)

@app.route("/delete_user/<username>", methods=["POST"])
@login_required
def delete_user(username):
    if current_user.username != "h":
        return render_template("error2.html", message="Access denied."), 403
    db.execute("DELETE FROM users WHERE username = ?", username)
    flash(f"User '{username}' deleted.")
    return redirect("/admin")

@app.route("/delete_users", methods=["POST"])
@login_required
def delete_users():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    users = request.get_json().get('users', [])
    for u in users:
        db.execute("DELETE FROM users WHERE username = ?", u)
    return jsonify(success=True)

@app.route("/delete_chats", methods=["POST"])
@login_required
def delete_chats():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    chats = request.get_json().get('chats', [])
    for c in chats:
        db.execute("DELETE FROM group_chats WHERE id = ?", c)
    return jsonify(success=True)

# --- IMAGE UPLOAD ---
UPLOAD_BASE = os.path.join(os.getcwd(), "IMAGES")

def delete_file_later(path, seconds=300):
    def remove():
        try:
            os.remove(path)
            group_folder = os.path.dirname(path)
            if not os.listdir(group_folder):
                os.rmdir(group_folder)
        except Exception as e:
            print(f"Failed to delete {path}: {e}")
    threading.Timer(seconds, remove).start()

@app.route("/IMAGES/<key>/", methods=["POST"])
@login_required
def upload_image(key):
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    filename = secure_filename(file.filename)
    group_path = os.path.join(UPLOAD_BASE, str(key))
    os.makedirs(group_path, exist_ok=True)
    full_path = os.path.join(group_path, filename)
    file.save(full_path)
    delete_file_later(full_path, 300)
    return jsonify({"image_url": url_for('serve_image', key=key, filename=filename)})

@app.route("/IMAGES/<key>/<filename>")
def serve_image(key, filename):
    return send_from_directory(os.path.join(UPLOAD_BASE, str(key)), filename)

# --- TIMEOUTS ---
timeouts = {}

@app.route("/mod", methods=["GET", "POST"])
@login_required
def mod_panel():
    if current_user.username.strip() not in ["h", "Diimi", "bu", "ct", "sanna"]:
        return render_template("error2.html", message="Access denied: Moderator privileges required."), 403
    if request.method == "POST":
        username = request.form.get("username")
        duration = int(request.form.get("timeout_duration"))
        if duration < 1 or duration > 60:
            flash("Invalid timeout duration!")
            return redirect(url_for("mod_panel"))
        timeouts[username] = (datetime.now() + timedelta(minutes=duration)).strftime("%Y-%m-%d %H:%M:%S")
        flash(f"User {username} timed out for {duration} minutes.")
        return redirect(url_for("mod_panel"))
    users = [{"username": u["username"]} for u in db.execute("SELECT username FROM users")]
    return render_template("mod.html", users=users, timeouts=timeouts)

@app.route("/check_timeout")
@login_required
def check_timeout():
    timeout_until = timeouts.get(current_user.username)
    if timeout_until and datetime.now() < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return jsonify({"timed_out": True})
    return jsonify({"timed_out": False})

@app.route("/timeout-canceled")
@login_required
def timeout_canceled():
    timeout_until = timeouts.get(current_user.username)
    if not timeout_until:
        return jsonify({"timeout_canceled": True})
    if datetime.now() < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return jsonify({"timeout_canceled": False})
    del timeouts[current_user.username]
    return jsonify({"timeout_canceled": True})

@app.route("/cancel_timeout/<username>", methods=["POST"])
@login_required
def cancel_timeout(username):
    if current_user.username not in ["h", "ct", "bu", "Diimi"]:
        return redirect(url_for("mod_panel"))
    if username in timeouts:
        del timeouts[username]
        flash(f"Timeout for {username} canceled.")
    return redirect(url_for("mod_panel"))

@app.route("/reset_messages", methods=["POST"])
@login_required
def reset_messages():
    if current_user.username != "h":
        return redirect("/admin")
    try:
        with open("messages.json", "w") as f:
            json.dump({}, f)
        flash("All messages reset.")
    except Exception as e:
        return render_template("error2.html", message=str(e))
    return redirect(url_for("admin"))

# --- SETTINGS ---
DEFAULT_SETTINGS = {"profile_pic": None, "theme": "light", "notifications": True, "panic_url": ""}

def get_settings_path(user_id):
    return os.path.join(SETTINGS_DIR, f"settings_{user_id}.pkl")

def load_user_settings(user_id):
    path = get_settings_path(user_id)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)
    return DEFAULT_SETTINGS.copy()

def save_user_settings(user_id, settings):
    with open(get_settings_path(user_id), "wb") as f:
        pickle.dump(settings, f)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    s = load_user_settings(current_user.id)
    if request.method == "POST":
        if "profile_pic" in request.files and request.files["profile_pic"].filename:
            file = request.files["profile_pic"]
            old_pic = s.get("profile_pic")
            if old_pic and old_pic != "default.png":
                old_path = os.path.join("static", "profile_pics", old_pic)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception:
                        pass
            filename = f"profile_{current_user.id}_{secure_filename(file.filename)}"
            filepath = os.path.join("static", "profile_pics", filename)
            file.save(filepath)
            try:
                with Image.open(filepath) as im:
                    im = im.convert("RGBA") if im.mode in ("P", "RGBA") else im.convert("RGB")
                    im = im.resize((100, 100), Image.LANCZOS)
                    im.save(filepath)
            except Exception as e:
                return render_template("error2.html", message=f"Error resizing: {str(e)}")
            s["profile_pic"] = filename
        if request.form.get("theme") in ["light", "dark", "yellow"]:
            s["theme"] = request.form.get("theme")
        s["notifications"] = request.form.get("notifications") == "on"
        s["panic_url"] = request.form.get("panic_url", "")
        new_password = request.form.get("new_password")
        if new_password:
            db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), current_user.id)
            flash("Password changed!")
        save_user_settings(current_user.id, s)
        resp = make_response(redirect(url_for("settings")))
        resp.set_cookie("notifications_enabled", "1" if s["notifications"] else "0")
        flash("Settings updated!")
        return resp
    return render_template("settings.html", settings=s, user=current_user)

@app.route("/delete_profile_pic/<username>", methods=["POST"])
@login_required
def delete_profile_pic(username):
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    user_row = db.execute("SELECT id FROM users WHERE username = ?", username)
    if not user_row:
        return jsonify({"error": "User not found"}), 404
    user_id = user_row[0]["id"]
    us = load_user_settings(user_id)
    old_pic = us.get("profile_pic")
    if old_pic and old_pic != "default.png":
        old_path = os.path.join("static", "profile_pics", old_pic)
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except Exception:
                pass
    us["profile_pic"] = "default.png"
    save_user_settings(user_id, us)
    return jsonify(success=True)

@app.route("/delete_all_profile_pics", methods=["POST"])
@login_required
def delete_all_profile_pics():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    all_users = db.execute("SELECT id FROM users")
    for u in all_users:
        us = load_user_settings(u["id"])
        old_pic = us.get("profile_pic")
        if old_pic and old_pic != "default.png":
            old_path = os.path.join("static", "profile_pics", old_pic)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except Exception:
                    pass
        us["profile_pic"] = "default.png"
        save_user_settings(u["id"], us)
    return jsonify(success=True)

# --- TYPING ---
TYPING_FILE = "typing.json"

def load_typing_data():
    if not os.path.exists(TYPING_FILE):
        return {}
    with open(TYPING_FILE, "r") as f:
        return json.load(f)

def save_typing_data(data):
    with open(TYPING_FILE, "w") as f:
        json.dump(data, f)

@app.route('/typing/<key>', methods=['POST'])
@login_required
def typing(key):
    data = load_typing_data()
    if key not in data:
        data[key] = {}
    data[key][current_user.username] = datetime.now(timezone.utc).isoformat()
    save_typing_data(data)
    return jsonify(success=True)

@app.route('/typing_stop/<key>', methods=['POST'])
@login_required
def typing_stop(key):
    data = load_typing_data()
    if key in data and current_user.username in data[key]:
        del data[key][current_user.username]
        save_typing_data(data)
    return jsonify(success=True)

@app.route('/typing_status/<key>')
@login_required
def typing_status(key):
    now = datetime.now(timezone.utc)
    data = load_typing_data()
    active = []
    changed = False
    if key in data:
        for username, last_time_str in list(data[key].items()):
            last_time = datetime.fromisoformat(last_time_str)
            if (now - last_time).total_seconds() > 3:
                del data[key][username]
                changed = True
            else:
                active.append(username)
        if changed:
            save_typing_data(data)
    return jsonify(typing=active)

@app.route('/terms')
def terms_and_conditions():
    return render_template('policy.html')

# --- FILE EXPLORER ---
def is_path_safe(base, target):
    return os.path.abspath(target).startswith(os.path.abspath(base))

@app.route('/files', defaults={'req_path': ''})
@app.route('/files/<path:req_path>')
@login_required
def files(req_path):
    if current_user.username != "h":
        abort(403)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.abspath(os.path.join(BASE_DIR, req_path))
    if not is_path_safe(BASE_DIR, abs_path):
        abort(403)
    if not os.path.exists(abs_path):
        return render_template("file_explorer.html", files=[], folders=[], parent="", current=req_path, error="Path does not exist.")
    if os.path.isfile(abs_path):
        return send_file(abs_path, as_attachment=True)
    items = os.listdir(abs_path)
    files_list = [i for i in items if os.path.isfile(os.path.join(abs_path, i))]
    folders = [i for i in items if os.path.isdir(os.path.join(abs_path, i))]
    parent = os.path.dirname(req_path)
    return render_template("file_explorer.html", files=files_list, folders=folders, parent=parent, current=req_path, error=None)

@app.route('/files_download/<path:req_path>')
@login_required
def files_download(req_path):
    if current_user.username != "h":
        abort(403)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.abspath(os.path.join(BASE_DIR, req_path))
    if not is_path_safe(BASE_DIR, abs_path) or not os.path.exists(abs_path):
        abort(404)
    if os.path.isfile(abs_path):
        return send_file(abs_path, as_attachment=True)
    zip_io = io.BytesIO()
    with zipfile.ZipFile(zip_io, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, flist in os.walk(abs_path):
            for file in flist:
                full_path = os.path.join(root, file)
                zf.write(full_path, arcname=os.path.relpath(full_path, abs_path))
    zip_io.seek(0)
    return send_file(zip_io, mimetype='application/zip', as_attachment=True, download_name=os.path.basename(abs_path) + ".zip")

@app.route('/files_view/<path:req_path>')
@login_required
def files_view(req_path):
    if current_user.username != "h":
        abort(403)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.abspath(os.path.join(BASE_DIR, req_path))
    if not abs_path.startswith(BASE_DIR) or not os.path.isfile(abs_path):
        abort(404)
    mimetype, _ = mimetypes.guess_type(abs_path)
    is_text = mimetype and mimetype.startswith("text")
    is_image = mimetype and mimetype.startswith("image")
    if os.path.getsize(abs_path) > 5 * 1024 * 1024:
        return render_template("file_viewer.html", filename=req_path, error="File too large to display.", content=None, is_text=False, is_image=False, image_url=None)
    if is_text:
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as e:
            return render_template("file_viewer.html", filename=req_path, error=str(e), content=None, is_text=False, is_image=False, image_url=None)
        return render_template("file_viewer.html", filename=req_path, content=content, error=None, is_text=True, is_image=False, image_url=None)
    if is_image:
        rel_path = os.path.relpath(abs_path, BASE_DIR)
        image_url = url_for('files_view_image', req_path=rel_path)
        return render_template("file_viewer.html", filename=req_path, content=None, error=None, is_text=False, is_image=True, image_url=image_url)
    return render_template("file_viewer.html", filename=req_path, content=None, error="Cannot display this file type.", is_text=False, is_image=False, image_url=None)

@app.route('/files_image/<path:req_path>')
@login_required
def files_view_image(req_path):
    if current_user.username != "h":
        abort(403)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    abs_path = os.path.abspath(os.path.join(BASE_DIR, req_path))
    if not abs_path.startswith(BASE_DIR) or not os.path.isfile(abs_path):
        abort(404)
    return send_file(abs_path)

if __name__ == "__main__":
    if not os.path.exists(UPLOAD_BASE):
        os.makedirs(UPLOAD_BASE)
    # Ensure group_chats table has 'custom' column
    try:
        db.execute("ALTER TABLE group_chats ADD COLUMN custom INTEGER DEFAULT 0")
    except Exception:
        pass  # Column already exists
    app.run(debug=True)
