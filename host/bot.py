import os
import json
import re
import subprocess
import psutil
import socket
import sys
import hashlib
import secrets
import time
import zipfile
import shutil
from datetime import datetime, timedelta
from flask import Flask, send_from_directory, request, jsonify, session, redirect, url_for, make_response, send_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_DIR = os.path.join(BASE_DIR, "USERS")
BOT_TEMPLATE_DIR = os.path.join(os.path.dirname(BASE_DIR), "bot_template")
os.makedirs(USERS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR)
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

running_procs = {}
USERS_FILE = os.path.join(BASE_DIR, "users.json")
REMEMBER_TOKENS_FILE = os.path.join(BASE_DIR, "remember_tokens.json")
PORTS_FILE = os.path.join(BASE_DIR, "ports.json")

ADMIN_USERNAME = "AlliFF121"
ADMIN_PASSWORD = "123123123"

def init_users_db():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            admin_data = {
                ADMIN_USERNAME: {
                    "password": hash_password(ADMIN_PASSWORD),
                    "created_at": datetime.now().isoformat(),
                    "last_login": None,
                    "theme": "premium",
                    "is_admin": True,
                    "can_create_users": True,
                    "max_bots": 999,
                    "expires_at": None
                }
            }
            json.dump(admin_data, f, indent=2)

def init_tokens_db():
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

def init_ports_db():
    if not os.path.exists(PORTS_FILE):
        with open(PORTS_FILE, "w", encoding="utf-8") as f:
            json.dump({"last_port": 1999, "assignments": {}}, f)

def get_next_port(username, folder):
    init_ports_db()
    with open(PORTS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    key = f"{username}_{folder}"
    if key in data["assignments"]:
        return data["assignments"][key]
    
    new_port = data["last_port"] + 1
    data["last_port"] = new_port
    data["assignments"][key] = new_port
    
    with open(PORTS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    return new_port

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_remember_token(username):
    init_tokens_db()
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    tokens[token] = {
        "username": username,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires,
        "last_used": datetime.now().isoformat()
    }
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    return token

def validate_remember_token(token):
    if not os.path.exists(REMEMBER_TOKENS_FILE):
        return None
    with open(REMEMBER_TOKENS_FILE, "r", encoding="utf-8") as f:
        tokens = json.load(f)
    if token not in tokens:
        return None
    token_data = tokens[token]
    expires_at = datetime.fromisoformat(token_data["expires_at"])
    if datetime.now() > expires_at:
        del tokens[token]
        with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=2)
        return None
    token_data["last_used"] = datetime.now().isoformat()
    tokens[token] = token_data
    with open(REMEMBER_TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    return token_data["username"]

def register_user(username, password, max_bots=1, days=30, created_by_admin=False):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    if username in users:
        return False, "المستخدم موجود بالفعل"
    if len(password) < 6:
        return False, "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
    
    expires_at = (datetime.now() + timedelta(days=int(days))).isoformat()
    
    users[username] = {
        "password": hash_password(password),
        "created_at": datetime.now().isoformat(),
        "last_login": None,
        "is_admin": username == ADMIN_USERNAME,
        "created_by_admin": created_by_admin,
        "created_by": session.get('username') if 'username' in session else None,
        "max_bots": int(max_bots),
        "expires_at": expires_at
    }
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    user_dir = os.path.join(USERS_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return True, "تم إنشاء الحساب بنجاح"

def authenticate_user(username, password):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    if username not in users:
        return False, "المستخدم غير موجود"
    
    user_data = users[username]
    if user_data["password"] != hash_password(password):
        return False, "كلمة المرور غير صحيحة"
    
    if not user_data.get("is_admin", False) and user_data.get("expires_at"):
        expires_at = datetime.fromisoformat(user_data["expires_at"])
        if datetime.now() > expires_at:
            return False, "انتهت صلاحية هذا الحساب"
            
    users[username]["last_login"] = datetime.now().isoformat()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    return True, "تم تسجيل الدخول بنجاح"

def is_admin(username):
    init_users_db()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)
    return users.get(username, {}).get("is_admin", False)

def get_user_bots_dir(username):
    return os.path.join(USERS_DIR, username, "BOTS")

def ensure_user_bots_dir():
    if 'username' not in session:
        return None
    user_dir = get_user_bots_dir(session['username'])
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def sanitize_folder_name(name):
    if not name: return ""
    name = name.strip()
    name = re.sub(r"\s+", "-", name)
    name = re.sub(r"[^A-Za-z0-9\-\_\.]", "", name)
    return name[:200]

def ensure_bot_meta(folder):
    user_bots_dir = ensure_user_bots_dir()
    if not user_bots_dir: return None
    meta_path = os.path.join(user_bots_dir, folder, "meta.json")
    if not os.path.exists(meta_path):
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"display_name": folder, "startup_file": "main.py"}, f)
    return meta_path

def get_bot_stats(pid):
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            cpu = proc.cpu_percent()
            mem = proc.memory_info().rss / (1024 * 1024)
            status = proc.status()
        return {"cpu": cpu, "mem": round(mem, 2), "status": status}
    except:
        return {"cpu": 0, "mem": 0, "status": "stopped"}

@app.before_request
def check_remember_token():
    if 'username' in session: return
    remember_token = request.cookies.get('remember_token')
    if remember_token:
        username = validate_remember_token(remember_token)
        if username:
            session['username'] = username
            session.permanent = True

@app.route("/")
def home():
    if 'username' not in session: return redirect(url_for('login_page'))
    if is_admin(session['username']): return send_from_directory(BASE_DIR, "admin_panel.html")
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/login")
def login_page():
    if 'username' in session: return redirect(url_for('home'))
    return send_from_directory(BASE_DIR, "login.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username, password = data.get("username", "").strip(), data.get("password", "").strip()
    remember = data.get("remember", False)
    success, message = authenticate_user(username, password)
    if success:
        session['username'] = username
        session.permanent = True
        resp = make_response(jsonify({"success": True, "message": message, "is_admin": is_admin(username)}))
        if remember:
            token = create_remember_token(username)
            resp.set_cookie('remember_token', token, max_age=30*24*60*60, httponly=True)
        return resp
    return jsonify({"success": False, "message": message})

@app.route("/api/logout")
def api_logout():
    token = request.cookies.get('remember_token')
    if token:
        if os.path.exists(REMEMBER_TOKENS_FILE):
            with open(REMEMBER_TOKENS_FILE, "r") as f: tokens = json.load(f)
            if token in tokens:
                del tokens[token]
                with open(REMEMBER_TOKENS_FILE, "w") as f: json.dump(tokens, f, indent=2)
    session.clear()
    resp = make_response(redirect(url_for('login_page')))
    resp.delete_cookie('remember_token')
    return resp

@app.route("/api/user/info")
def api_user_info():
    if 'username' not in session: return jsonify({}), 401
    with open(USERS_FILE, "r") as f: users = json.load(f)
    user_data = users.get(session['username'], {})
    return jsonify({
        "username": session['username'],
        "is_admin": user_data.get("is_admin", False),
        "max_bots": user_data.get("max_bots", 1),
        "expires_at": user_data.get("expires_at")
    })

@app.route("/api/bots/list")
def api_bots_list():
    if 'username' not in session: return jsonify([]), 401
    user_bots_dir = ensure_user_bots_dir()
    if not user_bots_dir: return jsonify([])
    bots = []
    for folder in os.listdir(user_bots_dir):
        bot_path = os.path.join(user_bots_dir, folder)
        if os.path.isdir(bot_path):
            meta_path = os.path.join(bot_path, "meta.json")
            meta = {}
            if os.path.exists(meta_path):
                with open(meta_path, "r") as f: meta = json.load(f)
            
            proc_key = f"{session['username']}_{folder}"
            # تحقق أكثر دقة من الحالة: إذا كان في القائمة، تأكد أنه لا يزال يعمل
            is_running = False
            if proc_key in running_procs:
                proc = running_procs[proc_key]
                try:
                    # التحقق مما إذا كان الكائن من psutil أو subprocess
                    if hasattr(proc, 'is_running'):
                        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                            is_running = True
                        else:
                            del running_procs[proc_key]
                    elif hasattr(proc, 'poll'):
                        if proc.poll() is None:
                            is_running = True
                        else:
                            del running_procs[proc_key]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    if proc_key in running_procs: del running_procs[proc_key]
            
            # فحص إضافي عبر psutil للتأكد من عدم وجود عمليات يتيمة
            if not is_running:
                for p in psutil.process_iter(['pid', 'name', 'cwd']):
                    try:
                        if p.info['name'] == 'python3' and p.info['cwd'] == bot_path:
                            is_running = True
                            # تحديث القائمة بالعملية الموجودة
                            running_procs[proc_key] = p
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            status = "running" if is_running else "stopped"
            bots.append({
                "folder": folder,
                "title": meta.get("display_name", folder),
                "status": status
            })
    return jsonify(bots)

@app.route("/api/bots/create", methods=["POST"])
def api_bots_create():
    if 'username' not in session: return jsonify({"success": False}), 401
    
    with open(USERS_FILE, "r") as f: users = json.load(f)
    user_data = users.get(session['username'], {})
    max_bots = user_data.get("max_bots", 1)
    
    user_bots_dir = ensure_user_bots_dir()
    current_bots = [f for f in os.listdir(user_bots_dir) if os.path.isdir(os.path.join(user_bots_dir, f))]
    
    if len(current_bots) >= max_bots:
        return jsonify({"success": False, "message": f"لقد وصلت للحد الأقصى من البوتات المسموح بها ({max_bots})"})

    data = request.get_json()
    name = sanitize_folder_name(data.get("name"))
    if not name: return jsonify({"success": False, "message": "اسم غير صالح"})
    
    path = os.path.join(user_bots_dir, name)
    if os.path.exists(path): return jsonify({"success": False, "message": "البوت موجود بالفعل"})
    
    # استنساخ قالب البوت
    shutil.copytree(BOT_TEMPLATE_DIR, path)
    
    # إنشاء ملف الإعدادات الافتراضي
    config_template = os.path.join(BOT_TEMPLATE_DIR, "config_template.json")
    with open(config_template, "r") as f: config = json.load(f)
    with open(os.path.join(path, "config.json"), "w") as f: json.dump(config, f, indent=2)
    
    ensure_bot_meta(name)
    return jsonify({"success": True})

@app.route("/api/bots/start", methods=["POST"])
def api_bots_start():
    if 'username' not in session: return jsonify({"success": False}), 401
    data = request.get_json()
    folder = data.get("folder")
    user_bots_dir = ensure_user_bots_dir()
    bot_path = os.path.join(user_bots_dir, folder)
    
    proc_key = f"{session['username']}_{folder}"
    if proc_key in running_procs and running_procs[proc_key].poll() is None:
        return jsonify({"success": False, "message": "البوت يعمل بالفعل"})
    
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    
    log_path = os.path.join(bot_path, "server.log")
    
    # دالة لتشغيل البوت مع تثبيت المكتبات أولاً
    def run_bot_task():
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"\n--- Bot Start Sequence at {datetime.now().isoformat()} ---\n")
            log_file.flush()
            
            # 1. تثبيت المكتبات
            if os.path.exists(os.path.join(bot_path, "requirements.txt")):
                log_file.write("[SYSTEM] Installing requirements...\n")
                log_file.flush()
                try:
                    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                                   cwd=bot_path, stdout=log_file, stderr=log_file, check=True)
                    log_file.write("[SYSTEM] Requirements installed successfully.\n")
                except Exception as e:
                    log_file.write(f"[SYSTEM] Error installing requirements: {str(e)}\n")
                log_file.flush()

            # 2. تشغيل البوت
            log_file.write("[SYSTEM] Starting main.py...\n")
            log_file.flush()
            
            try:
                # نفتح الملف مرة أخرى للـ Popen لضمان أننا نكتب في النهاية
                with open(log_path, "a", encoding="utf-8") as f:
                    proc = subprocess.Popen([sys.executable, "main.py"], 
                                          cwd=bot_path, 
                                          stdout=f, 
                                          stderr=f, 
                                          env=env, 
                                          start_new_session=True)
                    running_procs[proc_key] = proc
            except Exception as e:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"[SYSTEM] Critical Error: {str(e)}\n")

    # تشغيل في Thread منفصل لعدم حظر Flask
    import threading
    threading.Thread(target=run_bot_task).start()
    
    return jsonify({"success": True, "message": "بدأت عملية التشغيل، تحقق من السجل"})

@app.route("/api/bots/stop", methods=["POST"])
def api_bots_stop():
    if 'username' not in session: return jsonify({"success": False}), 401
    data = request.get_json()
    folder = data.get("folder")
    user_bots_dir = ensure_user_bots_dir()
    bot_path = os.path.join(user_bots_dir, folder)
    proc_key = f"{session['username']}_{folder}"
    
    # محاولة الإيقاف عبر القائمة
    if proc_key in running_procs:
        proc = running_procs[proc_key]
        try:
            parent = psutil.Process(proc.pid)
            for child in parent.children(recursive=True): child.kill()
            parent.kill()
        except: pass
        del running_procs[proc_key]
    
    # إيقاف قسري لأي عملية تعمل في نفس المجلد (لضمان الإيقاف التام)
    for p in psutil.process_iter(['pid', 'name', 'cwd']):
        try:
            if p.info['name'] == 'python3' and p.info['cwd'] == bot_path:
                parent = psutil.Process(p.info['pid'])
                for child in parent.children(recursive=True): child.kill()
                parent.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    return jsonify({"success": True})

@app.route("/api/bots/restart", methods=["POST"])
def api_bots_restart():
    stop_res = api_bots_stop()
    time.sleep(1)
    return api_bots_start()

@app.route("/api/bots/delete", methods=["POST"])
def api_bots_delete():
    if 'username' not in session: return jsonify({"success": False}), 401
    data = request.get_json()
    folder = data.get("folder")
    
    api_bots_stop()
        
    user_bots_dir = ensure_user_bots_dir()
    path = os.path.join(user_bots_dir, folder)
    if os.path.exists(path):
        shutil.rmtree(path)
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "البوت غير موجود"})

@app.route("/api/bots/config/get/<folder>")
def api_bots_config_get(folder):
    if 'username' not in session: return jsonify({}), 401
    user_bots_dir = ensure_user_bots_dir()
    config_path = os.path.join(user_bots_dir, folder, "config.json")
    if os.path.exists(config_path):
        with open(config_path, "r") as f: return jsonify(json.load(f))
    return jsonify({})

@app.route("/api/bots/config/save/<folder>", methods=["POST"])
def api_bots_config_save(folder):
    if 'username' not in session: return jsonify({"success": False}), 401
    data = request.get_json()
    user_bots_dir = ensure_user_bots_dir()
    config_path = os.path.join(user_bots_dir, folder, "config.json")
    with open(config_path, "w") as f: json.dump(data, f, indent=2)
    return jsonify({"success": True})

@app.route("/api/bots/logs/<folder>")
def api_bots_logs(folder):
    if 'username' not in session: return jsonify({"logs": ""}), 401
    user_bots_dir = ensure_user_bots_dir()
    log_path = os.path.join(user_bots_dir, folder, "server.log")
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            return jsonify({"logs": f.read()[-5000:]})
    return jsonify({"logs": ""})

@app.route("/api/admin/users")
def api_admin_users():
    if 'username' not in session or not is_admin(session['username']): return jsonify([]), 403
    with open(USERS_FILE, "r") as f: users = json.load(f)
    return jsonify([{
        "username": u, 
        "created_at": d["created_at"], 
        "last_login": d["last_login"],
        "max_bots": d.get("max_bots", 1),
        "expires_at": d.get("expires_at")
    } for u, d in users.items() if u != ADMIN_USERNAME])

@app.route("/api/admin/users/create", methods=["POST"])
def api_admin_users_create():
    if 'username' not in session or not is_admin(session['username']): return jsonify({"success": False}), 403
    data = request.get_json()
    return jsonify(register_user(
        data.get("username"), 
        data.get("password"), 
        data.get("max_bots", 1),
        data.get("days", 30),
        True
    ))

@app.route("/api/admin/users/delete", methods=["POST"])
def api_admin_users_delete():
    if 'username' not in session or not is_admin(session['username']): return jsonify({"success": False}), 403
    username = request.get_json().get("username")
    if username == ADMIN_USERNAME: return jsonify({"success": False})
    with open(USERS_FILE, "r") as f: users = json.load(f)
    if username in users:
        del users[username]
        with open(USERS_FILE, "w") as f: json.dump(users, f, indent=2)
        shutil.rmtree(os.path.join(USERS_DIR, username), ignore_errors=True)
    return jsonify({"success": True})

@app.route("/api/admin/stats")
def api_admin_stats():
    if 'username' not in session or not is_admin(session['username']): return jsonify({}), 403
    with open(USERS_FILE, "r") as f: users = json.load(f)
    total_size = sum(os.path.getsize(os.path.join(r, f)) for r, d, fs in os.walk(USERS_DIR) for f in fs)
    return jsonify({
        "total_users": len(users) - 1,
        "running_bots": len([p for p in running_procs.values() if p.poll() is None]),
        "storage_mb": round(total_size / (1024 * 1024), 2),
        "cpu_usage": psutil.cpu_percent(),
        "ram_usage": psutil.virtual_memory().percent
    })

if __name__ == "__main__":
    init_users_db()
    port = int(os.environ.get("PORT", os.environ.get("SERVER_PORT", 21047)))
    app.run(host="0.0.0.0", port=port, debug=False)
