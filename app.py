from flask import Flask, render_template, request, redirect, session, jsonify
from flask_cors import CORS
import sqlite3, bcrypt, secrets, jwt, datetime
from functools import wraps
import os

app = Flask(__name__)
CORS(app)  # 他アプリからのアクセスを許可
app.secret_key = secrets.token_hex(16)

DB = 'senin.db'
JWT_SECRET = secrets.token_hex(16)

# ---------- DB初期化 ----------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # ユーザー
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE,
                    password_hash TEXT
                )''')
    # APIキー
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    api_key TEXT,
                    app_name TEXT,
                    created_at TEXT
                )''')
    # アプリデータ
    c.execute('''CREATE TABLE IF NOT EXISTS app_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    app_name TEXT,
                    data TEXT,
                    created_at TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# ---------- JWT認証デコレータ ----------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"message":"Token is missing"}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = data['user_id']
        except:
            return jsonify({"message":"Token is invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# ---------- ユーザー登録 ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute('INSERT INTO users (user_id, password_hash) VALUES (?,?)', (user_id, pw_hash))
            conn.commit()
            conn.close()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "ユーザーIDは既に存在します"
    return render_template('register.html')

# ---------- ログイン ----------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE user_id=?', (user_id,))
        row = c.fetchone()
        conn.close()
        if row and bcrypt.checkpw(password.encode(), row[0]):
            session['user_id'] = user_id
            return redirect('/account')
        return "ログイン失敗"
    return render_template('index.html')

# ---------- アカウントページ ----------
@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    # APIキー取得
    c.execute('SELECT id, api_key, app_name, created_at FROM api_keys WHERE user_id=?', (user_id,))
    keys = c.fetchall()
    # アプリデータ一覧
    c.execute('SELECT id, app_name, data, created_at FROM app_data WHERE user_id=?', (user_id,))
    data_list = c.fetchall()
    conn.close()
    return render_template('account.html', user_id=user_id, api_keys=keys, app_data=data_list)

# ---------- APIキー発行 ----------
@app.route('/generate_apikey', methods=['POST'])
def generate_apikey():
    if 'user_id' not in session:
        return redirect('/login')
    user_id = session['user_id']
    app_name = request.form['app_name']
    api_key = secrets.token_urlsafe(32)
    created_at = datetime.datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('INSERT INTO api_keys (user_id, api_key, app_name, created_at) VALUES (?,?,?,?)',
              (user_id, api_key, app_name, created_at))
    conn.commit()
    conn.close()
    return redirect('/account')

# ---------- APIキー削除 ----------
@app.route('/delete_apikey/<int:key_id>', methods=['POST'])
def delete_apikey(key_id):
    if 'user_id' not in session:
        return redirect('/login')
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id=? AND user_id=?', (key_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect('/account')

# ---------- 他アプリ用ログインフォーム ----------
@app.route('/app_login', methods=['GET','POST'])
def app_login():
    if request.method == 'POST':
        user_id = request.form['user_id']
        password = request.form['password']
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE user_id=?', (user_id,))
        row = c.fetchone()
        conn.close()
        if row and bcrypt.checkpw(password.encode(), row[0]):
            # JWTトークン発行（他アプリ用）
            payload = {"user_id": user_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
            return jsonify({"status":"ok", "token":token})
        return jsonify({"status":"fail"})
    return render_template('app_login.html')

# ---------- アプリデータ保存 ----------
@app.route('/api/data', methods=['POST'])
@token_required
def save_data(current_user):
    data_json = request.json
    app_name = data_json.get('app_name')
    data_content = data_json.get('data')
    if not app_name or data_content is None:
        return jsonify({"status":"fail","message":"app_name or data missing"})
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('INSERT INTO app_data (user_id, app_name, data, created_at) VALUES (?,?,?,?)',
              (current_user, app_name, str(data_content), datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"status":"ok"})

# ---------- アプリデータ取得 ----------
@app.route('/api/data', methods=['GET'])
@token_required
def get_data(current_user):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('SELECT app_name, data, created_at FROM app_data WHERE user_id=?', (current_user,))
    rows = c.fetchall()
    conn.close()
    return jsonify({"status":"ok", "data":[{"app_name":r[0],"data":r[1],"created_at":r[2]} for r in rows]})

# ---------- アプリデータ削除 ----------
@app.route('/api/data/<app_name>', methods=['DELETE'])
@token_required
def delete_data(current_user, app_name):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('DELETE FROM app_data WHERE user_id=? AND app_name=?', (current_user, app_name))
    conn.commit()
    conn.close()
    return jsonify({"status":"ok"})

# ---------- Render用起動 ----------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

@app.route("/")
def root():
    return redirect("/login")
