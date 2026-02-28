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
from flask_login import logout_user
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="flask_login")

SETTINGS_DIR = "settings"
os.makedirs(SETTINGS_DIR, exist_ok=True)
os.makedirs(os.path.join("static", "profile_pics"), exist_ok=True)

db = SQL("sqlite:///logins.db")

app = Flask(__name__)
app.secret_key = "REPLACE_THIS_WITH_A_LONG_RANDOM_SECRET_KEY_12345"
app.config['MAX_CONTENT_LENGTH'] = 26 * 1024 * 1024

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- FILE LOCKING UTILITIES ---

_file_locks = {}
_file_locks_mutex = threading.Lock()

def get_file_lock(filepath):
    with _file_locks_mutex:
        if filepath not in _file_locks:
            _file_locks[filepath] = threading.Lock()
        return _file_locks[filepath]

def read_json_file(filepath):
    lock = get_file_lock(filepath)
    with lock:
        try:
            if not os.path.exists(filepath):
                return {}
            with open(filepath, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}

def write_json_file(filepath, data):
    lock = get_file_lock(filepath)
    with lock:
        tmp_path = filepath + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f)
            os.replace(tmp_path, filepath)
        except Exception as e:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except:
                    pass
            raise e

# --- PRESENCE / ONLINE STATUS ---
# Structure: { username: { "last_seen": float (unix timestamp), "source": "web"|"app", "focused": bool } }
_presence = {}
_presence_lock = threading.Lock()

ONLINE_THRESHOLD = 8    # seconds — actively online
AWAY_THRESHOLD   = 60   # seconds — away (tab hidden / app minimized)
# > AWAY_THRESHOLD = offline

def get_user_status(username):
    with _presence_lock:
        p = _presence.get(username)
    if not p:
        return "offline"
    age = time.time() - p["last_seen"]
    if age > AWAY_THRESHOLD:
        return "offline"
    if age > ONLINE_THRESHOLD or not p.get("focused", True):
        return "away"
    return "online"

@app.route("/heartbeat", methods=["POST"])
@login_required
def heartbeat():
    data = request.get_json(silent=True) or {}
    focused = data.get("focused", True)
    source  = data.get("source", "web")   # "web" or "app"
    with _presence_lock:
        _presence[current_user.username] = {
            "last_seen": time.time(),
            "focused":   focused,
            "source":    source,
        }
    return jsonify(success=True)

@app.route("/get_online_users")
@login_required
def get_online_users():
    all_users = db.execute("SELECT username FROM users")
    result = []
    for u in all_users:
        uname = u["username"]
        status = get_user_status(uname)
        with _presence_lock:
            p = _presence.get(uname, {})
        result.append({
            "username": uname,
            "status":   status,
            "source":   p.get("source", "web"),
        })
    return jsonify(users=result)

# --- USER ---

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    if not user:
        return None
    u = User()
    u.id       = user[0]['id']
    u.username = user[0]['username']
    u.emoji    = user[0]['emoji']
    return u

@app.context_processor
def inject_settings():
    if current_user.is_authenticated:
        return dict(settings=load_user_settings(current_user.id))
    return dict(settings=None)

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"]  = "no-cache"
    return response


# --- AUTH ---

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username     = request.form.get('username')
        password     = request.form.get('password')
        confirmation = request.form.get('confirmation')
        emoji        = request.form.get('emoji')
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
        u.id       = db.execute("SELECT id FROM users WHERE username = ?", username)[0]["id"]
        u.username = username
        u.emoji    = emoji
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
            return render_template("error.html", message="Invalid username and/or password")
        u = User()
        u.id       = rows[0]["id"]
        u.username = rows[0]["username"]
        u.emoji    = rows[0]["emoji"]
        login_user(u, remember=True)
        return redirect("/")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    # Mark offline immediately on logout
    with _presence_lock:
        _presence.pop(current_user.username, None)
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

MESSAGES_FILE = "messages.json"

@app.route("/messages/<key>")
@login_required
def get_messages(key):
    try:
        data = read_json_file(MESSAGES_FILE)
        return jsonify({"messages": data.get(str(key), [])})
    except Exception as e:
        return render_template("error2.html", message=f"error: {str(e)}")

def extract_mentions(text):
    return set(re.findall(r'@(\w+|everyone)', text or ""))

@app.route("/chat_room/<key>", methods=['POST'])
@login_required
def post_message(key):
    message   = request.json.get('message', '')
    image_url = request.json.get('image_url', None)
    file_url  = request.json.get('file_url', None)
    file_name = request.json.get('file_name', None)
    file_size = request.json.get('file_size', None)
    audio_url = request.json.get('audio_url', None)
    reply_to  = request.json.get('reply_to', None)
    if not message and not image_url and not file_url and not audio_url:
        return jsonify({"error": "Message cannot be empty."}), 400
    try:
        data = read_json_file(MESSAGES_FILE)
        if str(key) not in data:
            data[str(key)] = []
        user_settings = load_user_settings(current_user.id)
        profile_pic   = user_settings.get("profile_pic") or "default.png"
        msg_id        = str(uuid.uuid4())
        mentions      = extract_mentions(message)
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
            "id":        msg_id,
            "username":  current_user.username,
            "emoji":     current_user.emoji,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "profile_pic": profile_pic,
            "highlight": highlight,
            "mentions":  mentioned_users,
        }
        if message:   msg_data["message"]   = message
        if image_url: msg_data["image_url"] = image_url
        if file_url:
            msg_data["file_url"]  = file_url
            msg_data["file_name"] = file_name or "file"
            msg_data["file_size"] = file_size or 0
        if audio_url: msg_data["audio_url"] = audio_url
        if reply_to:  msg_data["reply_to"]  = reply_to
        data[str(key)].append(msg_data)
        write_json_file(MESSAGES_FILE, data)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/delete_message/<key>/<msg_id>", methods=['POST'])
@login_required
def delete_message(key, msg_id):
    try:
        data = read_json_file(MESSAGES_FILE)
        key  = str(key)
        if key in data:
            data[key] = [m for m in data[key]
                         if not (m.get("id") == msg_id and m.get("username") == current_user.username)]
        write_json_file(MESSAGES_FILE, data)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/chat", methods=['GET', 'POST'])
@login_required
def chat():
    timeout_until = timeouts.get(current_user.username)
    if timeout_until and datetime.now(timezone.utc).replace(tzinfo=None) < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
        return render_template("timeout.html", timeout_until=timeout_until)

    recent_groups = []
    try:
        data = read_json_file(MESSAGES_FILE)
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
    chat_group = db.execute("SELECT * FROM group_chats WHERE id = ?", str(key))
    if not chat_group:
        return render_template("error2.html", message="Invalid group code.")
    return render_template("chat_room.html", key=key)

@app.route("/get_users")
@login_required
def get_users():
    users = db.execute("SELECT username FROM users")
    return jsonify({"users": [u['username'] for u in users]})

@app.route("/get_group_members/<key>")
@login_required
def get_group_members(key):
    """Return list of users who have ever posted in this group, with their status."""
    data = read_json_file(MESSAGES_FILE)
    messages = data.get(str(key), [])
    seen = {}
    for msg in messages:
        uname = msg.get("username")
        if uname and uname not in seen:
            seen[uname] = msg.get("profile_pic", "default.png")
    result = []
    for uname, pic in seen.items():
        result.append({
            "username": uname,
            "profile_pic": pic,
            "status": get_user_status(uname),
        })
    # Sort: online first, then away, then offline
    order = {"online": 0, "away": 1, "offline": 2}
    result.sort(key=lambda x: (order.get(x["status"], 2), x["username"]))
    return jsonify(members=result)


# --- DIRECT MESSAGES ---

DM_FILE = "dms.json"

def load_dms():
    return read_json_file(DM_FILE)

def save_dms(data):
    write_json_file(DM_FILE, data)

def get_dm_key(user1, user2):
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
            "username":    other_username,
            "profile_pic": profile_pic,
            "unread":      0,
            "status":      get_user_status(other_username),
        })
    return render_template("dm.html", conversations=conversations, active_user=None, active_profile_pic="default.png")

@app.route("/dm/<username>")
@login_required
def dm_chat(username):
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
        conversations.append({
            "username":    other_username,
            "profile_pic": profile_pic,
            "unread":      0,
            "status":      get_user_status(other_username),
        })

    if not any(c["username"] == username for c in conversations) and username != current_user.username:
        row = db.execute("SELECT id FROM users WHERE username = ?", username)
        pp = "default.png"
        if row:
            s = load_user_settings(row[0]["id"])
            pp = s.get("profile_pic") or "default.png"
        conversations.insert(0, {"username": username, "profile_pic": pp, "unread": 0, "status": get_user_status(username)})

    active_pp = "default.png"
    row = db.execute("SELECT id FROM users WHERE username = ?", username)
    if row:
        s = load_user_settings(row[0]["id"])
        active_pp = s.get("profile_pic") or "default.png"

    return render_template("dm.html", conversations=conversations, active_user=username,
                           active_profile_pic=active_pp,
                           active_status=get_user_status(username))

@app.route("/dm_messages/<username>")
@login_required
def dm_messages(username):
    data = load_dms()
    key  = get_dm_key(current_user.username, username)
    return jsonify({"messages": data.get(key, [])})

@app.route("/send_dm", methods=['POST'])
@login_required
def send_dm():
    body      = request.json
    to_user   = body.get('to')
    message   = body.get('message', '')
    image_url = body.get('image_url', None)
    reply_to  = body.get('reply_to', None)
    if not to_user:
        return jsonify({"error": "No recipient specified"}), 400
    if not message and not image_url:
        return jsonify({"error": "Empty message"}), 400
    user_row = db.execute("SELECT id FROM users WHERE username = ?", to_user)
    if not user_row:
        return jsonify({"error": "User not found"}), 404

    user_settings = load_user_settings(current_user.id)
    profile_pic   = user_settings.get("profile_pic") or "default.png"
    msg_id = str(uuid.uuid4())
    msg_data = {
        "id":        msg_id,
        "username":  current_user.username,
        "emoji":     current_user.emoji,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile_pic": profile_pic,
    }
    if message:   msg_data["message"]   = message
    if image_url: msg_data["image_url"] = image_url
    if reply_to:  msg_data["reply_to"]  = reply_to

    data = load_dms()
    key  = get_dm_key(current_user.username, to_user)
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
        data[key] = [m for m in data[key]
                     if not (m.get("id") == msg_id and m.get("username") == current_user.username)]
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

def get_upload_folder_stats(base_path):
    result = []
    if not os.path.isdir(base_path):
        return result
    for folder_name in os.listdir(base_path):
        folder_path = os.path.join(base_path, folder_name)
        if not os.path.isdir(folder_path):
            continue
        files = []
        total_size = 0
        for fname in os.listdir(folder_path):
            fpath = os.path.join(folder_path, fname)
            if os.path.isfile(fpath):
                sz = os.path.getsize(fpath)
                total_size += sz
                files.append({"name": fname, "size": sz})
        result.append({"folder": folder_name, "files": files, "total_size": total_size})
    return result

@app.route("/admin")
@login_required
def admin():
    if current_user.username != "h":
        return render_template("error2.html", message="Access denied: Admin privileges required.")
    users       = db.execute("SELECT username, hash FROM users")
    group_chats = db.execute("SELECT id, custom FROM group_chats")
    images_base = os.path.join(os.getcwd(), "IMAGES")
    image_folders = {}
    if os.path.isdir(images_base):
        for key in os.listdir(images_base):
            folder_path = os.path.join(images_base, key)
            if os.path.isdir(folder_path):
                files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
                image_folders[key] = files
    base_dir     = os.path.dirname(os.path.abspath(__file__))
    root_size    = get_directory_size(base_dir)
    root_size_gb = root_size / (1024 ** 3)
    percent_used = min(100, root_size_gb * 100)

    dm_stats = None
    try:
        dms = load_dms()
        total_dm_msgs = sum(len(v) for v in dms.values())
        dm_stats = {"total": total_dm_msgs, "conversations": len(dms)}
    except Exception:
        pass

    upload_folders = get_upload_folder_stats(os.path.join(os.getcwd(), "UPLOADS"))
    audio_folders  = get_upload_folder_stats(os.path.join(os.getcwd(), "AUDIO"))

    # Online stats for admin
    all_users = db.execute("SELECT username FROM users")
    online_stats = []
    for u in all_users:
        uname = u["username"]
        with _presence_lock:
            p = _presence.get(uname, {})
        online_stats.append({
            "username": uname,
            "status":   get_user_status(uname),
            "source":   p.get("source", "-"),
            "last_seen": datetime.fromtimestamp(p["last_seen"]).strftime("%H:%M:%S") if p.get("last_seen") else "never",
        })

    return render_template("admin.html",
        users=users, group_chats=group_chats, image_folders=image_folders,
        root_size=root_size, root_size_gb=root_size_gb, percent_used=percent_used,
        dm_stats=dm_stats,
        upload_folders=upload_folders,
        audio_folders=audio_folders,
        online_stats=online_stats)

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

@app.route('/admin_delete_upload_folder/<folder>', methods=['POST'])
@login_required
def admin_delete_upload_folder(folder):
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    target = os.path.join(os.getcwd(), "UPLOADS", secure_filename(folder))
    if os.path.isdir(target):
        shutil.rmtree(target)
    return jsonify(success=True)

@app.route('/admin_delete_upload_file', methods=['POST'])
@login_required
def admin_delete_upload_file():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    data     = request.get_json()
    folder   = data.get('folder', '')
    filename = data.get('filename', '')
    target   = os.path.join(os.getcwd(), "UPLOADS", secure_filename(folder), secure_filename(filename))
    if os.path.isfile(target):
        os.remove(target)
    return jsonify(success=True)

@app.route('/admin_reset_uploads', methods=['POST'])
@login_required
def admin_reset_uploads():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    base = os.path.join(os.getcwd(), "UPLOADS")
    if os.path.isdir(base):
        shutil.rmtree(base)
    os.makedirs(base, exist_ok=True)
    return jsonify(success=True)

@app.route('/admin_delete_audio_folder/<folder>', methods=['POST'])
@login_required
def admin_delete_audio_folder(folder):
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    target = os.path.join(os.getcwd(), "AUDIO", secure_filename(folder))
    if os.path.isdir(target):
        shutil.rmtree(target)
    return jsonify(success=True)

@app.route('/admin_delete_audio_file', methods=['POST'])
@login_required
def admin_delete_audio_file():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    data     = request.get_json()
    folder   = data.get('folder', '')
    filename = data.get('filename', '')
    target   = os.path.join(os.getcwd(), "AUDIO", secure_filename(folder), secure_filename(filename))
    if os.path.isfile(target):
        os.remove(target)
    return jsonify(success=True)

@app.route('/admin_reset_audio', methods=['POST'])
@login_required
def admin_reset_audio():
    if current_user.username != "h":
        return jsonify({"error": "Unauthorized"}), 403
    base = os.path.join(os.getcwd(), "AUDIO")
    if os.path.isdir(base):
        shutil.rmtree(base)
    os.makedirs(base, exist_ok=True)
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
        time.sleep(seconds)
        try:
            if os.path.exists(path):
                os.remove(path)
            group_folder = os.path.dirname(path)
            if os.path.isdir(group_folder) and not os.listdir(group_folder):
                os.rmdir(group_folder)
        except Exception as e:
            print(f"Failed to delete {path}: {e}")
    t = threading.Thread(target=remove, daemon=True)
    t.start()

@app.route("/IMAGES/<key>/", methods=["POST"])
@login_required
def upload_image(key):
    if 'image' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    filename   = secure_filename(file.filename)
    group_path = os.path.join(UPLOAD_BASE, str(key))
    os.makedirs(group_path, exist_ok=True)
    full_path  = os.path.join(group_path, filename)
    file.save(full_path)
    delete_file_later(full_path, 300)
    return jsonify({"image_url": url_for('serve_image', key=key, filename=filename)})

@app.route("/IMAGES/<key>/<filename>")
def serve_image(key, filename):
    return send_from_directory(os.path.join(UPLOAD_BASE, str(key)), filename)


# --- FILE UPLOAD ---
FILES_BASE   = os.path.join(os.getcwd(), "UPLOADS")
os.makedirs(FILES_BASE, exist_ok=True)
MAX_FILE_SIZE = 25 * 1024 * 1024

@app.route("/upload_file/<key>", methods=["POST"])
@login_required
def upload_file(key):
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    file.seek(0, 2); file_size = file.tell(); file.seek(0)
    if file_size > MAX_FILE_SIZE:
        return jsonify({"error": "File too large. Max 25MB."}), 413
    original_name = secure_filename(file.filename)
    unique_name   = f"{uuid.uuid4().hex}_{original_name}"
    group_path    = os.path.join(FILES_BASE, str(key))
    os.makedirs(group_path, exist_ok=True)
    full_path = os.path.join(group_path, unique_name)
    file.save(full_path)
    delete_file_later(full_path, 3600)
    file_url = url_for('serve_upload', key=key, filename=unique_name)
    return jsonify({"file_url": file_url, "file_name": original_name, "file_size": file_size})

@app.route("/UPLOADS/<key>/<filename>")
@login_required
def serve_upload(key, filename):
    group_path = os.path.join(FILES_BASE, str(key))
    file_path  = os.path.join(group_path, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found or expired"}), 404
    return send_from_directory(group_path, filename, as_attachment=True)


# --- AUDIO UPLOAD ---
AUDIO_BASE = os.path.join(os.getcwd(), "AUDIO")
os.makedirs(AUDIO_BASE, exist_ok=True)

@app.route("/upload_audio/<key>", methods=["POST"])
@login_required
def upload_audio(key):
    if 'audio' not in request.files:
        return jsonify({"error": "No audio file"}), 400
    file = request.files['audio']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    file.seek(0, 2); file_size = file.tell(); file.seek(0)
    if file_size > MAX_FILE_SIZE:
        return jsonify({"error": "Audio file too large. Max 25MB."}), 413
    original_name = secure_filename(file.filename)
    unique_id     = uuid.uuid4().hex
    group_path    = os.path.join(AUDIO_BASE, str(key))
    os.makedirs(group_path, exist_ok=True)
    input_path    = os.path.join(group_path, f"{unique_id}_input_{original_name}")
    file.save(input_path)
    output_filename = f"{unique_id}_audio.mp3"
    output_path     = os.path.join(group_path, output_filename)
    try:
        from pydub import AudioSegment  # type: ignore
        audio = AudioSegment.from_file(input_path)
        audio = audio.set_channels(1)
        audio.export(output_path, format="mp3", bitrate="64k")
        os.remove(input_path)
    except Exception as e:
        output_filename = f"{unique_id}_input_{original_name}"
        output_path     = input_path
        print(f"Audio compression skipped: {e}")
    delete_file_later(output_path, 3600)
    audio_url = url_for('serve_audio', key=key, filename=output_filename)
    return jsonify({"audio_url": audio_url})

@app.route("/AUDIO/<key>/<filename>")
@login_required
def serve_audio(key, filename):
    group_path = os.path.join(AUDIO_BASE, str(key))
    file_path  = os.path.join(group_path, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "Audio not found or expired"}), 404
    mimetype, _ = mimetypes.guess_type(file_path)
    if not mimetype:
        mimetype = "audio/mpeg"
    return send_from_directory(group_path, filename, mimetype=mimetype)


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
        timeouts[username] = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=duration)).strftime("%Y-%m-%d %H:%M:%S")
        flash(f"User {username} timed out for {duration} minutes.")
        return redirect(url_for("mod_panel"))
    users = [{"username": u["username"]} for u in db.execute("SELECT username FROM users")]
    return render_template("mod.html", users=users, timeouts=timeouts)

@app.before_request
def update_last_active():
    session['last_active'] = datetime.now(timezone.utc).isoformat()

@app.route('/check_timeout')
def check_timeout():
    if current_user.is_authenticated:
        last_active_str = session.get('last_active')
        if last_active_str:
            try:
                last_active = datetime.fromisoformat(last_active_str)
                now         = datetime.now(timezone.utc)
                if now - last_active > timedelta(minutes=30):
                    logout_user()
                    return jsonify({"timed_out": True})
            except Exception:
                pass
    return jsonify({"timed_out": False})

@app.route("/timeout-canceled")
@login_required
def timeout_canceled():
    timeout_until = timeouts.get(current_user.username)
    if not timeout_until:
        return jsonify({"timeout_canceled": True})
    if datetime.now(timezone.utc).replace(tzinfo=None) < datetime.strptime(timeout_until, "%Y-%m-%d %H:%M:%S"):
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
        write_json_file(MESSAGES_FILE, {})
        flash("All messages reset.")
    except Exception as e:
        return render_template("error2.html", message=str(e))
    return redirect(url_for("admin"))


# --- SETTINGS ---
DEFAULT_SETTINGS = {"profile_pic": None, "theme": "light", "notifications": True, "panic_url": ""}

def get_settings_path(user_id):
    return os.path.join(SETTINGS_DIR, f"settings_{user_id}.pkl")

_settings_lock = threading.Lock()

def load_user_settings(user_id):
    path = get_settings_path(user_id)
    with _settings_lock:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    return pickle.load(f)
            except Exception:
                pass
    return DEFAULT_SETTINGS.copy()

def save_user_settings(user_id, settings):
    path     = get_settings_path(user_id)
    tmp_path = path + ".tmp"
    with _settings_lock:
        with open(tmp_path, "wb") as f:
            pickle.dump(settings, f)
        os.replace(tmp_path, path)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    s = load_user_settings(current_user.id)
    if request.method == "POST":
        if "profile_pic" in request.files and request.files["profile_pic"].filename:
            file    = request.files["profile_pic"]
            old_pic = s.get("profile_pic")
            if old_pic and old_pic != "default.png":
                old_path = os.path.join("static", "profile_pics", old_pic)
                if os.path.exists(old_path):
                    try: os.remove(old_path)
                    except Exception: pass
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
        s["panic_url"]     = request.form.get("panic_url", "")
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
    us      = load_user_settings(user_id)
    old_pic = us.get("profile_pic")
    if old_pic and old_pic != "default.png":
        old_path = os.path.join("static", "profile_pics", old_pic)
        if os.path.exists(old_path):
            try: os.remove(old_path)
            except Exception: pass
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
        us      = load_user_settings(u["id"])
        old_pic = us.get("profile_pic")
        if old_pic and old_pic != "default.png":
            old_path = os.path.join("static", "profile_pics", old_pic)
            if os.path.exists(old_path):
                try: os.remove(old_path)
                except Exception: pass
        us["profile_pic"] = "default.png"
        save_user_settings(u["id"], us)
    return jsonify(success=True)


# --- TYPING ---
_typing_data = {}
_typing_lock = threading.Lock()

@app.route('/typing/<key>', methods=['POST'])
@login_required
def typing(key):
    with _typing_lock:
        if key not in _typing_data:
            _typing_data[key] = {}
        _typing_data[key][current_user.username] = datetime.now(timezone.utc).isoformat()
    return jsonify(success=True)

@app.route('/typing_stop/<key>', methods=['POST'])
@login_required
def typing_stop(key):
    with _typing_lock:
        if key in _typing_data and current_user.username in _typing_data[key]:
            del _typing_data[key][current_user.username]
    return jsonify(success=True)

@app.route('/typing_status/<key>')
@login_required
def typing_status(key):
    now    = datetime.now(timezone.utc)
    active = []
    with _typing_lock:
        if key in _typing_data:
            expired = []
            for username, last_time_str in _typing_data[key].items():
                try:
                    last_time = datetime.fromisoformat(last_time_str)
                    if (now - last_time).total_seconds() > 3:
                        expired.append(username)
                    else:
                        active.append(username)
                except Exception:
                    expired.append(username)
            for u in expired:
                del _typing_data[key][u]
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
    items      = os.listdir(abs_path)
    files_list = [i for i in items if os.path.isfile(os.path.join(abs_path, i))]
    folders    = [i for i in items if os.path.isdir(os.path.join(abs_path, i))]
    parent     = os.path.dirname(req_path)
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
    is_text  = mimetype and mimetype.startswith("text")
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
        rel_path  = os.path.relpath(abs_path, BASE_DIR)
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
    try:
        db.execute("ALTER TABLE group_chats ADD COLUMN custom INTEGER DEFAULT 0")
    except Exception:
        pass
    app.run(debug=True)