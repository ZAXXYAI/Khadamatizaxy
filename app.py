from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, Blueprint
import sqlite3
import smtplib
from email.message import EmailMessage
import secrets  # لتوليد الرموز العشوائية
from flask_session import Session
import os
from dotenv import load_dotenv

load_dotenv()  # تحميل المتغيرات من .env
import os
from werkzeug.utils import secure_filename
from utils.ai_search import send_ai_query, API_KEYS
from chat import chat_bp
from flask import g
app = Flask(__name__)
from upgrade import add_upgrade_code, delete_upgrade_code, get_all_upgrade_codes, get_upgraded_users, manually_upgrade_user, get_manual_upgraded_users, apply_upgrade
DB_PATH = 'database/db.sqlite'
from datetime import datetime, timedelta
import bcrypt
from update_availability import update_user_availability
from upgrade_db import update_all_tables

 # حسب مكان الكود أعلاه
app.register_blueprint(chat_bp, url_prefix='/chat')
from chat import chat_bp  # حسب اسم ملفك

chat_api = Blueprint('chat_api', __name__)
# إعداد نظام الجلسات
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')# مفتاح الجلسة
Session(app)




DATABASE = 'database/db.sqlite'
from flask import Flask, flash, redirect, url_for
from update_availability import update_user_availability


@app.route('/admin/update-availability')
def trigger_update():
    count = update_user_availability()
    flash(f"✅ تم تحديث توفر المستخدمين. عدد من أصبح غير متاح: {count}", "success")
    return redirect(url_for('admin_panel'))  # غيّرها حسب اسم الصفحة
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # حتى تتمكن من الوصول للأعمدة بالاسم
    return g.db
def get_friend_requests(user_id):
    db = get_db()
    cursor = db.execute("""
        SELECT 
            friend_requests.id,
            friend_requests.sender_id,
            users.name AS sender_name,
            friend_requests.date_sent
        FROM friend_requests
        JOIN users ON friend_requests.sender_id = users.id
        WHERE friend_requests.receiver_id = ? AND friend_requests.status = 'pending'
        ORDER BY friend_requests.date_sent DESC
    """, (user_id,))
    return cursor.fetchall()


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# إعدادات البريد الإلكتروني
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
def get_db_connection():
    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/get_user_phone', methods=['GET'])
def get_user_phone():
    if 'user_id' not in session:
        return jsonify({'error': 'يجب تسجيل الدخول أولاً.'}), 401

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT phone FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'المستخدم غير موجود.'}), 404

    return jsonify({'phone': user[0]})

@app.route('/chatbot')  # واجهة الدردشة مع البوت
def chatbot_page():
    return render_template('chatbot.html')  # واجهة الدردشة مع البوت

@app.route('/chatbot/message', methods=['POST'])
def chatbot_message():
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    data = request.json
    user_id = session['user_id']
    user_message = data.get('message')

    if not user_message:
        return jsonify({'error': 'يجب إرسال رسالة!'}), 400

    bot_response = send_ai_query(user_id, user_message)

    # حفظ الرسائل
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, message, is_read)
        VALUES (?, ?, ?, ?)
    ''', (user_id, 0, user_message, 1))

    cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, message, is_read)
        VALUES (?, ?, ?, ?)
    ''', (0, user_id, bot_response, 1))

    conn.commit()
    conn.close()

    return jsonify({'response': bot_response})






# وظيفة لإرسال البريد الإلكتروني
from flask import flash

def send_email(email, subject, content, html=False):
    from email.message import EmailMessage
    import smtplib

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email

    if html:
        # HTML content
        msg.set_content("يرجى استخدام بريد يدعم HTML لرؤية المحتوى.")
        msg.add_alternative(content, subtype='html')
    else:
        # Plain text
        msg.set_content(content)

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception:
        return False
# الصفحة الرئيسية
@app.route('/')
def home():
    role = session.get('role')
    new_requests_count = 0
    reported_count = 0

    if role in ['admin', 'editor']:
        conn = sqlite3.connect('database/db.sqlite')
        cursor = conn.cursor()

        # عدد الطلبات الجديدة
        cursor.execute("SELECT COUNT(*) FROM pending_payments")
        new_requests_count = cursor.fetchone()[0]

        # عدد التقييمات المُبلّغ عنها (distinct باش ما يتكررش نفس التقييم)
        cursor.execute("SELECT COUNT(DISTINCT rating_id) FROM rating_reports")
        reported_count = cursor.fetchone()[0]

        conn.close()

    return render_template(
        'home.html',
        current_user=session.get('user'),
        new_requests_count=new_requests_count,
        reported_count=reported_count  # نبعثها للـ HTML
    )
# صفحة التسجيل
@app.route('/register', methods=['GET', 'POST'])
def register():
    admin_phone = os.getenv('ADMIN_PHONE')
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')  # رمز الأدمن

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        wilaya = request.form['wilaya']
        service_type = request.form['service_type']
        description = request.form['description']
        gender = request.form.get('gender', 'الكل')  # ✅ إضافة هذا السطر فقط
        admin_token = request.form.get('admin_token')  # حقل كلمة السر الخاصة بالأدمن
        verification_token = secrets.token_hex(4)

        if phone == admin_phone and email != admin_email:
            return render_template('register.html', error="🚫 رقم الهاتف غير مصرح به.")

        if email == admin_email and phone != admin_phone:
            return render_template('register.html', error="🚫 البريد الإلكتروني غير مصرح به.")

        if phone == admin_phone and email == admin_email:
            if admin_token != admin_password:
                return render_template('register.html', error="🔒 كلمة سر الأدمن خاطئة.", show_admin_field=True)

        conn = sqlite3.connect('database/db.sqlite')
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE phone = ?", (phone,))
        phone_exists = cursor.fetchone()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        email_exists = cursor.fetchone()

        if phone_exists or email_exists:
            conn.close()
            if phone_exists and email_exists:
                error_message = "❌ رقم الهاتف والبريد الإلكتروني مسجلين من قبل."
            elif phone_exists:
                error_message = "❌ رقم الهاتف هذا مسجل من قبل."
            elif email_exists:
                error_message = "❌ البريد الإلكتروني هذا مسجل من قبل."
            return render_template('register.html', error=error_message)

        if not (phone.startswith(('05', '06', '07')) and len(phone) == 10 and phone.isdigit()):
            conn.close()
            error_message = "📱 رقم الهاتف غير صحيح، جرب مرة أخرى من فضلك."
            return render_template('register.html', error=error_message)

        email_sent = send_email(
            email,
            'رمز التحقق من حسابك في خدماتي',
            f'رمز التحقق الخاص بك هو: {verification_token}'
        )

        if not email_sent:
            conn.close()
            return render_template('register.html', error="⚠️ فشل إرسال البريد الإلكتروني. تحقق من الاتصال.")

        cursor.execute('''
            INSERT INTO users (name, phone, email, password, wilaya, service_type, description, gender, verification_token, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ''', (name, phone, email, hashed_password, wilaya, service_type, description, gender, verification_token))
        conn.commit()

        session['pending_registration'] = {
            'name': name,
            'phone': phone,
            'email': email,
            
            'wilaya': wilaya,
            'service_type': service_type,
            'description': description,
            'gender': gender,
            'verification_token': verification_token
        }

        conn.close()
        return redirect(url_for('verify'))

    return render_template('register.html')
    
    
@app.route('/ignore_report', methods=['POST'])
def ignore_report():
    if 'phone' not in session or session.get('role') not in ['admin', 'editor']:
        return redirect(url_for('login'))

    rating_id = request.form.get('rating_id')

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    try:
        # حذف البلاغات الخاصة بهذا التقييم فقط
        cursor.execute('DELETE FROM rating_reports WHERE rating_id = ?', (rating_id,))
        conn.commit()
        flash("✅ تم تجاهل البلاغ بنجاح.")
    except Exception as e:
        conn.rollback()
        flash(f"❌ خطأ: {e}")
    finally:
        conn.close()

    return redirect(url_for('reported_ratings'))    
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    pending_data = session.get('pending_registration')

    if not pending_data:
        flash("⚠️ انتهت صلاحية الجلسة، يرجى التسجيل مجددًا.", "error")
        return redirect(url_for('register'))

    email = pending_data.get('email')

    if request.method == 'POST':
        entered_token = request.form['token'].strip()

        with sqlite3.connect('database/db.sqlite') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT verification_token FROM users WHERE email = ?', (email,))
            result = cursor.fetchone()

            if result and entered_token == result[0]:
                cursor.execute('UPDATE users SET is_verified = 1 WHERE email = ?', (email,))
                conn.commit()
                flash("✅ تم التحقق من حسابك بنجاح!", "success")
                return redirect(url_for('login'))
            else:
                error_message = "❌ رمز التحقق غير صحيح، حاول مرة أخرى."
                return render_template('verify.html', error=error_message)

    return render_template('verify.html')

# صفحة تسجيل الدخول
from flask import flash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form['phone']
        password = request.form['password']
        admin_key_input = request.form.get('admin_key')
        ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY')

        conn = sqlite3.connect('database/db.sqlite')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # جلب المستخدم
        cursor.execute('SELECT * FROM users WHERE phone = ?', (phone,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            user_id = user['id']
            email = user['email']
            is_verified = user['is_verified']
            role = user['role']
            is_superadmin = user['is_superadmin'] if 'is_superadmin' in user.keys() else 0

            # تحقق إذا كان المستخدم محظور
            # تحقق إذا كان المستخدم محظور (إلا إذا كان superadmin)
            cursor.execute('SELECT * FROM block WHERE user_id = ?', (user_id,))
            blocked = cursor.fetchone()
            if blocked and not is_superadmin:
                conn.close()
                flash("❌ لقد تم حظرك من الدخول إلى المنصة.", "error")
                return render_template('login.html')

            # تحقق من الأدمن الرئيسي
            ADMIN_PHONE = os.getenv('ADMIN_PHONE')
            ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')

            if phone == ADMIN_PHONE and email == ADMIN_EMAIL and is_verified == 1:
                if admin_key_input is None:
                    conn.close()
                    return render_template('login.html', show_admin_key=True)

                elif admin_key_input == ADMIN_SECRET_KEY:
                    # تعيين كـ superadmin إن لم يكن كذلك
                    if is_superadmin != 1:
                        cursor.execute("UPDATE users SET is_superadmin = 1 WHERE id = ?", (user_id,))
                        conn.commit()

                    # تعيين كـ admin إن لم يكن كذلك
                    if role != 'admin':
                        cursor.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
                        conn.commit()

                    # جلب البيانات المحدّثة
                    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
                    user = cursor.fetchone()
                    role = user['role']
                    is_superadmin = user['is_superadmin']
                else:
                    conn.close()
                    return render_template('login.html', error="❌ رمز الأدمن غير صحيح.", show_admin_key=True)

            elif phone == ADMIN_PHONE:
                conn.close()
                return render_template('login.html', error="❌ لا تملك صلاحية الدخول كأدمن.")

            # ✅ تسجيل الدخول
            session['user_id'] = user_id
            session['phone'] = user['phone']
            session['email'] = email
            session['role'] = role
            session['is_superadmin'] = is_superadmin

            conn.close()
            return redirect(url_for('home'))

        else:
            conn.close()
            return render_template('login.html', error="❌ رقم الهاتف أو كلمة المرور غير صحيحة.")

    return render_template('login.html')


@app.route('/check-admin-login', methods=['POST'])
def check_admin_login():
    data = request.get_json()
    phone = data.get('phone')
    password = data.get('password')

    # قراءة بيانات الأدمن من البيئة
    ADMIN_PHONE = os.getenv('ADMIN_PHONE')
    ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')

    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE phone = ?", (phone,))
    user = cursor.fetchone()
    conn.close()

    if user:
        stored_password = user['password']
        email = user['email']
        is_verified = user['is_verified']

        if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            if phone == ADMIN_PHONE and email == ADMIN_EMAIL and is_verified == 1:
                return jsonify({'is_admin': True})

    return jsonify({'is_admin': False})

# صفحة نسيت كلمة المرور
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = sqlite3.connect('database/db.sqlite')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            reset_token = secrets.token_hex(4)
            cursor.execute('UPDATE users SET reset_token = ? WHERE email = ?', (reset_token, email))
            conn.commit()
            conn.close()

            reset_link = f"https://khadamatizaxy.onrender.com/reset_password?token={reset_token}"

            # محتوى الإيميل بـ HTML
            html_content = f"""
            <p>🔑 لإعادة تعيين كلمة المرور، <a href="{reset_link}">اضغط هنا</a>.</p>
            <p>إذا لم تطلب هذا، تجاهل هذه الرسالة.</p>
            """

            send_email(email, 'إعادة تعيين كلمة المرور', html_content, html=True)
            success_message = "📧 تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني."
            return render_template('forgot_password.html', success=success_message)
        else:
            conn.close()
            error_message = "❌ البريد الإلكتروني غير مسجل، حاول مرة أخرى."
            return render_template('forgot_password.html', error=error_message)

    return render_template('forgot_password.html')

@app.route('/user/<int:user_id>')
def public_profile(user_id):
    db = get_db()

    # جلب بيانات المستخدم
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return "⚠️ المستخدم غير موجود", 404

    # 🔒 التحقق من حالة الحظر
    block = db.execute('SELECT 1 FROM block WHERE user_id = ?', (user_id,)).fetchone()
    is_blocked = block is not None

    # جلب التقييمات (تمت إضافة r.customer_id فقط)
    ratings = db.execute('''
        SELECT 
            r.id, 
            r.rating, 
            r.comment, 
            r.date_rated, 
            r.customer_id, 
            u.name AS customer_name,
            (SELECT COUNT(*) FROM rating_reports WHERE rating_id = r.id) AS report_count
        FROM ratings r
        JOIN users u ON r.customer_id = u.id
        WHERE r.worker_id = ?
        ORDER BY r.date_rated DESC
    ''', (user_id,)).fetchall()

    # حساب متوسط التقييم
    average_rating = None
    if ratings:
        total = sum([r['rating'] for r in ratings])
        average_rating = round(total / len(ratings), 2)

    # جلب الأصدقاء من جدول friends (لكل من لديه علاقة صداقة معه)
    user_friends = db.execute('''
        SELECT u.*
        FROM friends f
        JOIN users u ON u.id = f.friend_id
        WHERE f.user_id = ?
        UNION
        SELECT u.*
        FROM friends f
        JOIN users u ON u.id = f.user_id
        WHERE f.friend_id = ?
    ''', (user_id, user_id)).fetchall()

    return render_template('public_user.html',
                           user=user,
                           ratings=ratings,
                           average_rating=average_rating,
                           user_friends=user_friends,
                           is_blocked=is_blocked)



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("❌ كلمة المرور وتأكيدها غير متطابقين!", "error")
            return redirect(request.url)

        # تشفير كلمة المرور الجديدة
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = sqlite3.connect('database/db.sqlite')
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?', (hashed_password, token))
        conn.commit()
        conn.close()

        flash("✅ تم إعادة تعيين كلمة المرور بنجاح!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')




@app.route('/search_users', methods=['GET'])
def search_users():
    query = request.args.get('query', '').strip()
    wilaya = request.args.get('wilaya', 'all')
    gender = request.args.get('gender', 'الكل')

    did_search = bool(query or wilaya != 'all' or gender != 'الكل')

    if did_search:
        phone = session.get('phone')
        if not phone:
            flash("🔒 يرجى تسجيل الدخول أولاً", "warning")
            return redirect(url_for('login'))

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT is_upgraded, upgrade_date, upgrade_duration_days 
            FROM users 
            WHERE phone = ?
        ''', (phone,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            flash("❌ المستخدم غير موجود", "danger")
            return redirect(url_for('upgrade_page'))

        is_upgraded, upgrade_date_str, duration_days = result
        upgrade_date = parse_date_safe(upgrade_date_str)

        is_valid_upgrade = False
        if is_upgraded and upgrade_date:
            expiry_date = upgrade_date + timedelta(days=duration_days or 0)
            if datetime.now() <= expiry_date:
                is_valid_upgrade = True

        if not is_valid_upgrade:
            flash("⚠️ لا يمكنك استخدام البحث بدون ترقية صالحة.", "warning")
            return redirect(url_for('upgrade_page'))

    # متابعة البحث عادي
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    sql = """
    SELECT id, name, phone, email, wilaya, gender, image_path, service_type
    FROM users
    WHERE role != 'admin'
    """
    params = []

    if query:
        sql += " AND (name LIKE ? OR phone LIKE ? OR email LIKE ?)"
        q = f"%{query}%"
        params += [q, q, q]

    if wilaya != 'all':
        sql += " AND wilaya = ?"
        params.append(wilaya)

    if gender != 'الكل':
        sql += " AND gender = ?"
        params.append(gender)

    cursor.execute(sql, params)
    users = [
        {
            'id': row[0],
            'name': row[1],
            'phone': row[2],
            'email': row[3],
            'wilaya': row[4],
            'gender': row[5],
            'image_path': row[6],
            'service_type': row[7]
        }
        for row in cursor.fetchall()
    ]
    conn.close()

    return render_template('users_search.html', users=users, query=query, wilaya=wilaya, gender=gender)
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        service_type = request.form['service_type']
        wilaya = request.form['wilaya']
        gender = request.form.get('gender')  # ✅ قراءة الجنس من النموذج
        show_phone = 1 if request.form.get('show_phone') == 'on' else 0  # ✅ السطر المضاف
        conn = sqlite3.connect('database/db.sqlite')
        cursor = conn.cursor()

        # ✅ تجهيز الاستعلام حسب ما إذا تم اختيار الجنس أم لا
        if wilaya == 'all':
            if gender:
                cursor.execute('''
                    SELECT id, name, service_type, wilaya, description, is_available, image_path, phone, show_phone
                    FROM users
                    WHERE service_type = ? AND is_available = 1 AND gender = ?
                ''', (service_type, gender))
            else:
                cursor.execute('''
                    SELECT id, name, service_type, wilaya, description, is_available, image_path, phone, show_phone
                    FROM users
                    WHERE service_type = ? AND is_available = 1
                ''', (service_type,))
        else:
            if gender:
                cursor.execute('''
                    SELECT id, name, service_type, wilaya, description, is_available, image_path, phone, show_phone
                    FROM users
                    WHERE service_type = ? AND wilaya = ? AND is_available = 1 AND gender = ?
                ''', (service_type, wilaya, gender))
            else:
                cursor.execute('''
                    SELECT id, name, service_type, wilaya, description, is_available, image_path, phone, show_phone
                    FROM users
                    WHERE service_type = ? AND wilaya = ? AND is_available = 1
                ''', (service_type, wilaya))

        results = cursor.fetchall()

        users = []
        for row in results:
            user_id = row[0]
            # حساب متوسط التقييم وعدد التقييمات
            cursor.execute('''
                SELECT AVG(rating), COUNT(*) FROM ratings WHERE worker_id = ?
            ''', (user_id,))
            rating_data = cursor.fetchone()
            average_rating = round(rating_data[0], 1) if rating_data[0] else "لا يوجد"
            total_ratings = rating_data[1]

            user = {
                'id': user_id,
                'name': row[1],
                'service_type': row[2],
                'wilaya': row[3],
                'description': row[4],
                'is_available': row[5],
                'image_path': row[6],
                'phone': row[7],
                'average_rating': average_rating,
                'total_ratings': total_ratings,
                'show_phone': row[8]
            }   
            users.append(user)

        conn.close()
        return render_template('search.html', results=users)

    return render_template('search.html')
    conn.close()
    return True 
@app.route('/friend_requests')
def friend_requests():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # جلب بيانات المستخدم الحالي
    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    # جلب طلبات الصداقة الواردة مع الصورة
    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT fr.id, fr.date_sent, u.id as sender_id, u.name, u.phone, u.email, u.service_type, u.image_path, show_phone
    FROM friend_requests fr
    JOIN users u ON fr.sender_id = u.id
    WHERE fr.receiver_id = ? AND fr.status = 'pending'
    """, (user_id,))
    friend_requests = cursor.fetchall()
    conn.close()
    show_phone = 1 if request.form.get('show_phone') == 'on' else 0  # ✅ السطر المضاف

    return render_template('friend_requests.html', user=dict(user), friend_requests=friend_requests)



from datetime import datetime

@app.route('/rate', methods=['GET', 'POST'])
def rate():
    if 'phone' not in session:
        return redirect(url_for('login'))

    message = None
    worker_id = request.args.get('worker_id') or request.form.get('worker_id')

    if request.method == 'POST':
        rating = request.form['rating']
        comment = request.form.get('comment', '')
        phone = session['phone']

        conn = sqlite3.connect('database/db.sqlite')
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT id FROM users WHERE phone = ?', (phone,))
            result = cursor.fetchone()
            if result is None:
                message = "❌ خطأ: المستخدم غير موجود."
            else:
                customer_id = result[0]

                cursor.execute('SELECT id FROM users WHERE id = ?', (worker_id,))
                if cursor.fetchone() is None:
                    message = "⚠️ العامل غير موجود."
                else:
                    cursor.execute('SELECT id FROM ratings WHERE worker_id = ? AND customer_id = ?', (worker_id, customer_id))
                    if cursor.fetchone():
                        message = "❗ لقد قمت بتقييم هذا العامل مسبقًا."
                    else:
                        date_rated = datetime.now().strftime('%Y-%m-%d %H:%M')  # بدون ثواني
                        cursor.execute('''
                            INSERT INTO ratings (worker_id, customer_id, rating, comment, date_rated)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (worker_id, customer_id, rating, comment, date_rated))
                        conn.commit()
                        message = "✅ تم إرسال التقييم بنجاح!"
        except Exception as e:
            conn.rollback()
            message = f"❌ حدث خطأ: {e}"
        finally:
            conn.close()

    return render_template('rate.html', worker_id=worker_id, message=message)





@app.route('/delete_rating', methods=['POST'])
def delete_rating():
    if session.get('role') not in ['admin', 'editor']:
        flash("🚫 غير مصرح لك بحذف التقييم.")
        return redirect(request.referrer or url_for('home'))

    rating_id = request.form.get('rating_id')

    if not rating_id:
        flash("❌ معرف التقييم غير موجود.")
        return redirect(request.referrer or url_for('home'))

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    try:
        # ✅ أولاً نحذف التبليغات المتعلقة بهذا التقييم
        cursor.execute('DELETE FROM rating_reports WHERE rating_id = ?', (rating_id,))
        # ✅ ثم نحذف التقييم نفسه
        cursor.execute('DELETE FROM ratings WHERE id = ?', (rating_id,))
        conn.commit()
        flash("✅ تم حذف التقييم والتبليغات المرتبطة به بنجاح.")
    except Exception as e:
        conn.rollback()
        flash(f"❌ حدث خطأ أثناء الحذف: {e}")
    finally:
        conn.close()

    return redirect(request.referrer or url_for('home'))

# الأشهر بالعربية
from datetime import datetime

arabic_months = {
    1: 'جانفي', 2: 'فيفري', 3: 'مارس', 4: 'أفريل',
    5: 'ماي', 6: 'جوان', 7: 'جويلية', 8: 'أوت',
    9: 'سبتمبر', 10: 'أكتوبر', 11: 'نوفمبر', 12: 'ديسمبر'
}

@app.template_filter('datetimeformat')
def datetimeformat(value):
    if value is None:
        return ''

    # نحاول نقرأ التاريخ بصيغ مختلفة (مع أو بدون ثواني)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
        try:
            dt = datetime.strptime(value, fmt)
            break
        except ValueError:
            continue
    else:
        return value  # إذا ما قدرش يحوّل، يرجع النص كما هو

    day = dt.day
    month = arabic_months.get(dt.month, dt.strftime('%B'))
    year = dt.year
    time = dt.strftime('%H:%M')

    return f'📅 {day} {month} {year} - ⏰ {time}'



# إعداد مجلد لرفع الصور
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
from datetime import datetime, timedelta

def parse_date_safe(date_str):
    if not isinstance(date_str, str):
        return None  # مثلاً القيمة None أو رقم

    for fmt in ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'phone' not in session:
        return redirect(url_for('login'))

    phone = session['phone']  

    if request.method == 'POST':  
        name = request.form['name']  
        wilaya = request.form['wilaya']  
        service_type = request.form['service_type']  
        description = request.form['description']  
        requested_availability = 1 if request.form.get('is_available') == 'on' else 0  
        show_phone = 1 if request.form.get('show_phone') == 'on' else 0  # ✅ السطر المضاف

        conn = sqlite3.connect('database/db.sqlite')  
        cursor = conn.cursor()  

        cursor.execute('''  
            SELECT image_path, is_upgraded, upgrade_date, upgrade_duration_days  
            FROM users  
            WHERE phone = ?  
        ''', (phone,))  
        result = cursor.fetchone()  

        if not result:  
            conn.close()  
            return "❌ المستخدم غير موجود"  

        old_image_path, is_upgraded, upgrade_date_str, duration_days = result  

        if requested_availability == 1:  
            is_valid_upgrade = False  
            upgrade_date = parse_date_safe(upgrade_date_str)  
            if is_upgraded and upgrade_date:  
                expiry_date = upgrade_date + timedelta(days=duration_days or 0)  
                if datetime.now() <= expiry_date:  
                    is_valid_upgrade = True  

            if not is_valid_upgrade:  
                conn.close()  
                flash("⚠️ لا يمكنك تفعيل 'أنا متاح' بدون ترقية صالحة.", "warning")  
                return redirect(url_for('upgrade_page'))  

        # معالجة الصورة  
        if 'image' in request.files:  
            file = request.files['image']  
            if file.filename != '':  
                filename = secure_filename(file.filename)  
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)  
                file.save(file_path)  
                image_path = f"/static/uploads/{filename}"  
            else:  
                image_path = old_image_path  
        else:  
            image_path = old_image_path  

        # ✅ تحديث البيانات مع show_phone
        cursor.execute('''  
            UPDATE users  
            SET name = ?, wilaya = ?, service_type = ?, description = ?, is_available = ?, image_path = ?, show_phone = ?  
            WHERE phone = ?  
        ''', (name, wilaya, service_type, description, requested_availability, image_path, show_phone, phone))  

        conn.commit()  
        conn.close()  
        flash("✅ تم تحديث معلوماتك بنجاح", "success")  
        return redirect(url_for('profile'))  

    # --------------------------  
    # الطريقة GET: عرض بيانات المستخدم والتقييمات  
    # --------------------------  
    conn = sqlite3.connect('database/db.sqlite')  
    cursor = conn.cursor()  
    cursor.execute('SELECT * FROM users WHERE phone = ?', (phone,))  
    user_data = cursor.fetchone()  

    if not user_data:  
        conn.close()  
        return "المستخدم غير موجود!"  

    cursor.execute('SELECT * FROM ratings WHERE worker_id = ?', (user_data[0],))  
    ratings_data = cursor.fetchall()  
    conn.close()  

    ratings = [{  
        'rating': row[3],  
        'comment': row[4],  
        'date_rated': row[5]  
    } for row in ratings_data]  

    user = {  
        'name': user_data[1],  
        'phone': user_data[2],  
        'email': user_data[3],  
        'wilaya': user_data[5],  
        'service_type': user_data[7],  
        'description': user_data[8],  
        'image_path': user_data[9],  
        'is_available': user_data[10],  
        'ratings': ratings  ,
        'show_phone': user_data[16],
        
    }  

    # معالجة حالة الترقية  
    upgrade_status = "not_upgraded"  
    days_left = None  

    is_upgraded = user_data[17]  
    upgrade_date = parse_date_safe(user_data[18])  
    upgrade_duration_days = user_data[19]  

    if upgrade_date and upgrade_duration_days and is_upgraded:  
        expiry_date = upgrade_date + timedelta(days=upgrade_duration_days)  
        delta = (expiry_date - datetime.now())  
        days_left = max(0, delta.days)  
        upgrade_status = "active" if delta.days > 0 else "not_upgraded"  
    else:  
        # تحقق من وجود طلب قيد الانتظار  
        conn = sqlite3.connect(DB_PATH)  
        cursor = conn.cursor()  
        cursor.execute('SELECT COUNT(*) FROM pending_payments WHERE identifier = ?', (user_data[2],))  # user_data[2] = phone  
        has_pending = cursor.fetchone()[0] > 0  
        conn.close()  
        if has_pending:  
            upgrade_status = "pending"  

    user['upgrade_status'] = upgrade_status  
    user['days_left'] = days_left  
    
    return render_template('profile.html', user=user)

        
from flask import flash

@app.route('/logout')
def logout():
    session.clear()
    
    return redirect(url_for('home'))


# إرسال طلب صداقة


# وظيفة مساعدة للاتصال بقاعدة البيانات

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # جلب قائمة الأصدقاء مع بيانات إضافية
        cursor.execute('''
        SELECT users.id, users.name, users.phone, users.service_type, users.image_path
        FROM friends
        JOIN users ON friends.friend_id = users.id
        WHERE friends.user_id = ?
        ''', (user_id,))
        friends = cursor.fetchall()

        conn.close()
        return render_template('friends.html', friends=friends)
    except sqlite3.Error as e:
        return f"حدث خطأ أثناء جلب قائمة الأصدقاء: {e}"
   
        
# إرسال طلب صداقة
# إرسال طلب صداقة
@app.route('/send_friend_request/<int:receiver_id>', methods=['POST'])
def send_friend_request(receiver_id):
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    sender_id = session['user_id']
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # تحقق من وجود طلب صداقة مسبقًا
        cursor.execute('''
            SELECT 1 FROM friend_requests
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ''', (sender_id, receiver_id, receiver_id, sender_id))
        if cursor.fetchone():
            return jsonify({'error': 'طلب الصداقة موجود مسبقًا!'}), 409

        # إرسال طلب الصداقة
        cursor.execute('''
            INSERT INTO friend_requests (sender_id, receiver_id, status)
            VALUES (?, ?, ?)
        ''', (sender_id, receiver_id, 'pending'))

        conn.commit()
        return jsonify({'message': 'تم إرسال طلب الصداقة بنجاح!'}), 200
    except sqlite3.Error as e:
        return jsonify({'error': f"حدث خطأ أثناء إرسال طلب الصداقة: {e}"}), 500
    finally:
        conn.close()

@app.route('/cancel_friend_request/<int:receiver_id>', methods=['POST'])
def cancel_friend_request(receiver_id):
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    sender_id = session['user_id']
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # إلغاء طلب الصداقة
        cursor.execute('''
            DELETE FROM friend_requests
            WHERE sender_id = ? AND receiver_id = ?
        ''', (sender_id, receiver_id))

        conn.commit()
        return jsonify({'message': 'تم إلغاء طلب الصداقة بنجاح!'}), 200
    except sqlite3.Error as e:
        return jsonify({'error': f"حدث خطأ أثناء إلغاء طلب الصداقة: {e}"}), 500
    finally:
        conn.close()
# قبول طلب صداقة
@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # التحقق من أن المستقبل هو من يقبل الطلب
        cursor.execute('''
            SELECT sender_id, receiver_id FROM friend_requests
            WHERE id = ? AND receiver_id = ?
        ''', (request_id, session['user_id']))
        result = cursor.fetchone()

        if not result:
            return jsonify({'error': 'طلب الصداقة غير موجود أو غير مصرح لك بقبوله!'}), 404

        sender_id, receiver_id = result

        # تحديث حالة الطلب إلى "مقبول"
        cursor.execute('''
            UPDATE friend_requests
            SET status = 'accepted'
            WHERE id = ?
        ''', (request_id,))

        # إضافة العلاقة إلى جدول الأصدقاء من الطرفين
        cursor.execute('''
            INSERT INTO friends (user_id, friend_id)
            VALUES (?, ?)
        ''', (sender_id, receiver_id))

        cursor.execute('''
            INSERT INTO friends (user_id, friend_id)
            VALUES (?, ?)
        ''', (receiver_id, sender_id))

        conn.commit()
        return jsonify({'message': 'تم قبول طلب الصداقة!'}), 200

    except sqlite3.Error as e:
        return jsonify({'error': f"حدث خطأ أثناء قبول طلب الصداقة: {e}"}), 500

    finally:
        conn.close()

# إلغاء طلب صداقة

@app.route('/delete_friend/<int:friend_id>', methods=['POST'])
def delete_friend(friend_id):
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    user_id = session['user_id']
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # حذف العلاقة من جدول الأصدقاء من الطرفين
        # حذف العلاقة من جدول الأصدقاء ومن جدول الطلبات
        cursor.execute('''
            DELETE FROM friends
            WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
        ''', (user_id, friend_id, friend_id, user_id))

        cursor.execute('''
            DELETE FROM friend_requests
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ''', (user_id, friend_id, friend_id, user_id))

        conn.commit()
        return jsonify({'message': 'تم حذف الصديق بنجاح!'}), 200

    except sqlite3.Error as e:
        return jsonify({'error': f"حدث خطأ أثناء حذف الصديق: {e}"}), 500

    finally:
        conn.close()

# رفض طلب صداقة
@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
def reject_friend_request(request_id):
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    current_user_id = session['user_id']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # حذف الطلب بعد التأكد من أن المستقبل هو من يرفض الطلب
        cursor.execute('''
            DELETE FROM friend_requests
            WHERE id = ? AND receiver_id = ?
        ''', (request_id, current_user_id))

        conn.commit()
        return jsonify({'message': 'تم رفض طلب الصداقة!'}), 200

    except sqlite3.Error as e:
        return jsonify({'error': f"حدث خطأ أثناء رفض طلب الصداقة: {e}"}), 500

    finally:
        conn.close()
@app.route('/check_notifications')
def check_notifications():
    user_id = session.get('user_id')
    role = session.get('role')

    if not user_id:
        return jsonify({'error': 'غير مصرح'})

    conn = get_db_connection()
    cursor = conn.cursor()

    # طلبات الصداقة
    cursor.execute('''
        SELECT COUNT(*) FROM friend_requests
        WHERE receiver_id = ? AND status = 'pending'
    ''', (user_id,))
    new_friend_requests = cursor.fetchone()[0]

    # الرسائل غير المقروءة
    cursor.execute('''
        SELECT COUNT(*) FROM messages
        WHERE receiver_id = ? AND is_read = 0
    ''', (user_id,))
    new_messages = cursor.fetchone()[0]

    # عدد طلبات الترقية
    new_upgrade_requests = 0
    reported_ratings_count = 0  # ⬅️ تعريف المتغير

    if role in ['admin', 'editor']:
        cursor.execute("SELECT COUNT(*) FROM pending_payments")
        new_upgrade_requests = cursor.fetchone()[0]

        # ⬅️ جلب عدد التقييمات المبلّغ عنها
        cursor.execute("SELECT COUNT(DISTINCT rating_id) FROM rating_reports")
        reported_ratings_count = cursor.fetchone()[0]

    conn.close()

    return jsonify({
        'new_friend_requests': new_friend_requests,
        'new_messages': new_messages,
        'new_upgrade_requests': new_upgrade_requests,
        'reported_ratings_count': reported_ratings_count  # ⬅️ إرسال القيمة
    })
@app.route('/check_friendship_status/<int:receiver_id>', methods=['GET'])
def check_friendship_status(receiver_id):
    if 'user_id' not in session:
        return jsonify({'error': 'غير مصرح'}), 401

    sender_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # هل هما أصدقاء؟
        cursor.execute('''
            SELECT 1 FROM friends
            WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
        ''', (sender_id, receiver_id, receiver_id, sender_id))
        if cursor.fetchone():
            return jsonify({'status': 'friends'}), 200

        # هل هناك طلب صداقة معلق؟
        cursor.execute('''
            SELECT id, sender_id FROM friend_requests
            WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
            AND status = 'pending'
        ''', (sender_id, receiver_id, receiver_id, sender_id))
        row = cursor.fetchone()
        if row:
            request_id, sender = row
            direction = 'received' if sender != sender_id else 'sent'
            return jsonify({
                'status': 'pending',
                'direction': direction,
                'request_id': request_id
            }), 200

        return jsonify({'status': 'none'}), 200
    finally:
        conn.close()
        
        
        


@app.route('/remove_manual_upgrade', methods=['POST'])
def remove_manual_upgrade():
    role = session.get('role')

    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('admin_panel'))

    email = request.form['email']

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    # تحقق إذا الترقية يدوية (upgrade_code = NULL)
    cursor.execute("""
        SELECT is_upgraded, upgrade_code
        FROM users
        WHERE email = ?
    """, (email,))
    
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash(f"❌ لم يتم العثور على المستخدم {email}.", "danger")
        return redirect(url_for('admin_panel'))

    is_upgraded, upgrade_code = user

    if not is_upgraded:
        conn.close()
        flash(f"ℹ️ المستخدم {email} غير مفعّل حالياً.", "info")
        return redirect(url_for('admin_panel'))

    if upgrade_code is not None:
        conn.close()
        flash(f"❌ لا يمكن إزالة الترقية لأن المستخدم {email} تمت ترقيته بكود.", "danger")
        return redirect(url_for('admin_panel'))

    # إزالة الترقية اليدوية
    cursor.execute("""
        UPDATE users
        SET is_upgraded = 0,
            upgrade_date = NULL,
            upgrade_duration_days = NULL
        WHERE email = ? AND upgrade_code IS NULL
    """, (email,))

    conn.commit()
    conn.close()

    flash(f"✅ تم إزالة الترقية اليدوية للمستخدم {email}.", "success")
    return redirect(url_for('admin_panel'))








@app.route('/admin')
def admin_panel():
    role = session.get('role')

    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('home'))
    upgraded_users = get_upgraded_users()
    manual_users = get_manual_upgraded_users()
    all_codes = get_all_upgrade_codes()

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    # جلب المستخدمين لي عندهم دور غير user
    cursor.execute("SELECT name, phone, email, role FROM users WHERE role != 'user'")
    non_user_roles = [
        {'name': r[0], 'phone': r[1], 'email': r[2], 'role': r[3]} for r in cursor.fetchall()
    ]

    # جلب المحظورين
    cursor.execute("SELECT email, name, phone FROM users WHERE is_banned = 1")
    banned_users = cursor.fetchall()

    # ✅ إضافة: جلب عدد طلبات الترقية غير المعالجة
    cursor.execute("SELECT COUNT(*) FROM pending_payments")
    new_requests_count = cursor.fetchone()[0]

    conn.close()

    return render_template(
        'admin.html',
        upgraded_users=upgraded_users,
        manual_users=manual_users,
        all_codes=all_codes,
        banned_users=banned_users,
        non_user_roles=non_user_roles,
        new_requests_count=new_requests_count  # ✅ ضروري تمريره هنا
    )
@app.route('/admin/codes')
def admin_codes():
    role = session.get('role')

    if role != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('home'))

    all_codes = get_all_upgrade_codes()
    upgraded_users = get_upgraded_users()

    # ✅ جلب المستخدمين المحظورين من قاعدة البيانات
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT email, name, phone FROM users WHERE is_banned = 1")
    banned_users = cursor.fetchall()
    conn.close()

    return render_template(
        'admin_codes.html',
        all_codes=all_codes,
        upgraded_users=upgraded_users,
        banned_users=banned_users  # ✅ تمرير المتغير
    )
    
@app.route('/admin/add_code', methods=['POST'])
def add_code():
    role = session.get('role')

    # 🛑 التحقق من الصلاحية
    if role not in ['admin', 'editor']:
        return "🚫 غير مصرح لك", 403

    code = request.form.get('code')
    assigned_to = request.form.get('assigned_to')

    success, message = add_upgrade_code(code, assigned_to)
    
    flash(message, "success" if success else "danger")
    
    return redirect(url_for('admin_codes'))  # ✅ تأكد من التوجيه للصفحة المناسبة
@app.route('/admin/delete_code', methods=['POST'])
def delete_code():
    role = session.get('role')
    
    # 🛑 تحقق من الصلاحية
    if role not in ['admin', 'editor']:
        return "🚫 غير مصرح لك", 403


    code = request.form.get('code')
    # احذف الترقية من المستخدم الذي استعمل هذا الكود
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE users
    SET is_upgraded = 0,
        upgrade_code = NULL,
        upgrade_date = NULL,
        upgrade_duration_days = 0
    WHERE upgrade_code = ?
    ''', (code,))
    conn.commit()
    conn.close()

# ثم احذف الكود من الجدول
    delete_upgrade_code(code)
    flash("🗑️ تم حذف الكود", "info")
    return redirect(url_for('admin_codes'))


@app.route('/admin/update_columns', methods=['POST'])
def update_columns():
    role = session.get('role')

    if role != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('admin_panel'))

    update_all_tables()  # تحدث جميع الجداول
    flash("✅ تم تحديث جميع أعمدة قاعدة البيانات بنجاح", "success")
    return redirect(url_for('admin_panel'))


@app.route('/admin/update_availability', methods=['POST'])
def update_availability():
    role = session.get('role')
    if role not in ['admin', 'editor']:

        flash("🚫 ليس لديك صلاحية لتحديث التوفر", "danger")
        return redirect(url_for('home'))
    count = update_user_availability()
    if count > 0:
        flash(f"✅ تم إلغاء {count} متاحين وتحويلهم إلى غير متاح", "success")
    else:
        flash("ℹ️ لم يتم إلغاء أي حالة متاحة. لا يوجد تغييرات ضرورية.", "info")

    return redirect(url_for('home'))

@app.route('/admin/ban_user', methods=['POST'])
def ban_user():
    role = session.get('role')

    # ✅ فقط admin أو editor يقدروا يحظروا مستخدمين
    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('home'))

    user_email = request.form.get('email')

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    # تأكد أن المستخدم موجود قبل الحظر
    cursor.execute("SELECT email FROM users WHERE email = ?", (user_email,))
    if not cursor.fetchone():
        conn.close()
        flash("❌ المستخدم غير موجود", "danger")
        return redirect(url_for('admin_codes'))

    # ✅ حظر المستخدم
    cursor.execute("UPDATE users SET is_banned = 1 WHERE email = ?", (user_email,))

    # ✅ إزالة الترقية في نفس الوقت
    cursor.execute('''
        UPDATE users
        SET is_upgraded = 0,
            upgrade_code = NULL,
            upgrade_date = NULL,
            upgrade_duration_days = 0
        WHERE email = ?
    ''', (user_email,))

    conn.commit()
    conn.close()

    flash(f"🚫 تم حظر {user_email}", "warning")
    return redirect(url_for('admin_codes'))


@app.route('/admin/unban_user', methods=['POST'])
def unban_user():
    role = session.get('role')

    # ✅ فقط admin أو editor يقدروا يرفعوا الحظر
    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('home'))
    user_email = request.form.get('email')

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    # تأكد أن المستخدم موجود قبل إلغاء الحظر
    cursor.execute("SELECT email FROM users WHERE email = ?", (user_email,))
    if not cursor.fetchone():
        conn.close()
        flash("❌ المستخدم غير موجود", "danger")
        return redirect(url_for('admin_panel'))

    cursor.execute("UPDATE users SET is_banned = 0 WHERE email = ?", (user_email,))
    conn.commit()
    conn.close()

    flash(f"✅ تم رفع الحظر عن {user_email}", "success")
    return redirect(url_for('admin_codes'))
@app.route('/admin/active_upgrades')
def active_upgrades():
    role = session.get('role')

    # فقط admin أو editor يقدرو يدخلوا
    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('home'))
    # استدعاء البيانات مثلاً
    upgrades = get_active_upgrades()  # يجب أن تكون دالة ترجع الترقيات الفعالة

    return render_template("active_upgrades.html", upgrades=upgrades)

        
@app.route('/admin/manual_upgrade', methods=['POST'])
def manual_upgrade():
    role = session.get('role')

    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('admin_panel'))
    identifier = request.form.get('identifier', '').strip()
    days = int(request.form.get('days', 0))

    if not identifier:
        flash("❌ المرجو إدخال بريد إلكتروني أو رقم هاتف", "danger")
        return redirect(url_for('admin_panel'))

    from upgrade import manually_upgrade_user
    success, message = manually_upgrade_user(identifier, days)
    flash(message, "success" if success else "danger")
    return redirect(url_for('admin_panel')) 
    
# تأكد أنك أضفت هذا الاستيراد

@app.route('/manage_roles', methods=['GET', 'POST'])
def manage_roles():
    if session.get('role') != 'admin':
        flash("🚫 فقط المشرف (admin) يمكنه تنفيذ هذا الإجراء", "danger")
        return redirect(url_for('home'))

    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 🟡 معالجة POST لتحديث الدور
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        new_role = request.form.get('new_role')

        if not identifier or new_role not in ['admin', 'editor', 'user']:
            flash("❌ تحقق من البيانات المدخلة.", "error")
        else:
            cursor.execute('SELECT id, role, is_superadmin FROM users WHERE phone = ? OR email = ?', (identifier, identifier))
            user = cursor.fetchone()

            if user:
                user_id, current_role, is_superadmin = user

                # 🔐 حماية الأدمن الرئيسي
                if is_superadmin == 1:
                    flash("🚫 لا يمكن تعديل صلاحيات الأدمن الرئيسي.", "danger")
                elif current_role == new_role:
                    flash(f"ℹ️ المستخدم لديه بالفعل الدور: {new_role}", "info")
                else:
                    cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
                    conn.commit()

# ✅ إذا كان المستخدم الذي تم تغيير دوره هو نفسه الموجود في الجلسة
                    if session.get('user_id') == user_id:
                        session.clear()
                        flash("⚠️ تم تغيير صلاحياتك. الرجاء تسجيل الدخول مجددًا.", "warning")
                        return redirect(url_for('login'))
                    flash(f"✅ تم تحديث دور المستخدم إلى: {new_role}", "success")
            else:
                flash("❌ لم يتم العثور على مستخدم بهذا الرقم أو الإيميل.", "error")

    # 🔄 إرجاع الدور إلى user
    revoke_id = request.args.get("revoke_id")
    if revoke_id:
        try:
            cursor.execute('SELECT is_superadmin FROM users WHERE id = ?', (revoke_id,))
            target = cursor.fetchone()
            if target and target['is_superadmin'] == 1:
                flash("🚫 لا يمكن تغيير دور الأدمن الرئيسي.", "danger")
            else:
                cursor.execute('UPDATE users SET role = "user" WHERE id = ?', (revoke_id,))
                conn.commit()
                flash("🗑️ تم إرجاع المستخدم إلى مستخدم عادي.", "success")
        except Exception as e:
            flash(f"❌ حدث خطأ أثناء الإزالة: {e}", "error")

    # ✅ إلغاء الحظر
    unblock_id = request.args.get("unblock_id")
    if unblock_id:
        try:
            cursor.execute('DELETE FROM block WHERE user_id = ?', (unblock_id,))
            conn.commit()
            flash("🔓 تم إلغاء الحظر عن المستخدم.", "success")
        except Exception as e:
            flash(f"❌ لم يتم إلغاء الحظر: {e}", "error")

    # 🗑️ حذف نهائي
    delete_id = request.args.get("delete_id")
    if delete_id:
        try:
            cursor.execute('SELECT is_superadmin FROM users WHERE id = ?', (delete_id,))
            target = cursor.fetchone()
            if target and target['is_superadmin'] == 1:
                flash("🚫 لا يمكن حذف الأدمن الرئيسي.", "danger")
            else:
                cursor.execute('DELETE FROM block WHERE user_id = ?', (delete_id,))
                cursor.execute('DELETE FROM users WHERE id = ?', (delete_id,))
                cursor.execute('DELETE FROM ratings WHERE worker_id = ? OR customer_id = ?', (delete_id, delete_id))
                cursor.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (delete_id, delete_id))
                cursor.execute('DELETE FROM friend_requests WHERE sender_id = ? OR receiver_id = ?', (delete_id, delete_id))
                cursor.execute('DELETE FROM friends WHERE user_id = ? OR friend_id = ?', (delete_id, delete_id))
                conn.commit()
                flash("🗑️ تم حذف المستخدم وكل بياناته بنجاح.", "success")
        except Exception as e:
            flash(f"❌ حدث خطأ أثناء الحذف النهائي: {e}", "error")

    # 👥 جلب المستخدمين غير العاديين
    cursor.execute("SELECT id, name, phone, email, role FROM users WHERE role != 'user'")
    non_user_roles = cursor.fetchall()

    # 🚫 جلب المحظورين من جدول block
    cursor.execute('''
        SELECT u.id, u.name, u.phone, u.email, b.reason, b.date_blocked
        FROM block b
        JOIN users u ON u.id = b.user_id
        ORDER BY b.date_blocked DESC
    ''')
    blocked_users = cursor.fetchall()

    conn.close()

    return render_template(
        "manage_roles.html",
        non_user_roles=non_user_roles,
        blocked_users=blocked_users
    )
        
@app.route('/upgrade_page', methods=['GET', 'POST'])
def upgrade_page():
    if 'email' not in session:
        return redirect(url_for('login'))

    user_email = session['email']

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # جلب المحررين/الإداريين
    cursor.execute('SELECT name, phone, email, role FROM users WHERE role = "editor"')
    non_user_roles = [
        {'name': row[0], 'phone': row[1], 'email': row[2], 'role': row[3]}
        for row in cursor.fetchall()
    ]

    message = None
    message_type = None

    if request.method == 'POST':
        code = request.form.get('code')

        success, response = apply_upgrade(user_email, code)

        if success:
            message = response  # ✅ تمت الترقية بنجاح
            message_type = "success"
        else:
            message = response  # رسالة خطأ منطقية
            message_type = "error"

    conn.close()

    return render_template('upgrade_page.html',
                           non_user_roles=non_user_roles,
                           message=message,
                           message_type=message_type)


UPLOADE_FOLDER = 'static/payment_proofs'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
DB_PATH = 'database/db.sqlite'  # تأكد من المسار الصحيح

app.config['UPLOADE_FOLDER'] = UPLOADE_FOLDER
os.makedirs(UPLOADE_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route('/submit_payment', methods=['POST'])
def submit_payment():
    email_or_phone = request.form.get('email_or_phone', '').strip()
    note = request.form.get('note', '')
    image = request.files.get('payment_image')

    if not email_or_phone or not image:
        flash("⚠️ يرجى إدخال البيانات كاملة", "error")
        return redirect(url_for('upgrade_page'))

    if not allowed_file(image.filename):
        flash("⚠️ صيغة الصورة غير مدعومة (png/jpg/jpeg فقط)", "error")
        return redirect(url_for('upgrade_page'))

    # تحقق من وجود المستخدم
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ? OR phone = ?", (email_or_phone, email_or_phone))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash("❌ لا يوجد مستخدم بهذا البريد أو رقم الهاتف", "error")
        return redirect(url_for('upgrade_page'))

    # حفظ الصورة
    clean_identifier = email_or_phone.replace('@', '_at_').replace('.', '_').replace('+', '_')
    file_ext = image.filename.rsplit('.', 1)[1].lower()
    filename = secure_filename(f"{clean_identifier}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file_ext}")
    filepath = os.path.join(app.config['UPLOADE_FOLDER'], filename)
    image.save(filepath)

    # تحديث جدول users
    cursor.execute('''
        UPDATE users
        SET payment_proof_path = ?, payment_note = ?
        WHERE email = ? OR phone = ?
    ''', (filepath, note, email_or_phone, email_or_phone))

    # إضافة الطلب لجدول pending_payments
    cursor.execute('''
        INSERT INTO pending_payments (identifier, note, payment_proof_path)
        VALUES (?, ?, ?)
    ''', (email_or_phone, note, filepath))

    conn.commit()
    conn.close()

    flash("✅ تم إرسال إثبات الدفع بنجاح، سيتم مراجعة طلبك قريبًا.", "success")
    return redirect(url_for('upgrade_page'))






from math import floor

from datetime import datetime, timedelta
from math import floor

@app.route('/admin/upgrade_requests')
def admin_upgrade_requests():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # جلب الطلبات المعلقة (الغير معالجة)
    cursor.execute('''
        SELECT p.identifier, p.note, p.payment_proof_path, p.created_at, u.name, u.phone
        FROM pending_payments p
        LEFT JOIN users u ON p.identifier = u.phone
    ''')
    rows = cursor.fetchall()

    # نحسب عدد الطلبات
    new_requests_count = len(rows)

    conn.close()

    def parse_date_safe(date_str):
        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None

    def time_ago(dt_str):
        dt = parse_date_safe(dt_str)
        if not dt:
            return "تاريخ غير معروف"

        now = datetime.now() + timedelta(hours=-1)  # تعويض فرق التوقيت
        diff = now - dt

        total_seconds = diff.total_seconds()
        days = floor(total_seconds / 86400)
        hours = floor((total_seconds % 86400) / 3600)
        minutes = floor((total_seconds % 3600) / 60)

        if days >= 365:
            years = days // 365
            remaining_days = days % 365
            return f"منذ {years} سنة و{remaining_days} يوم" if remaining_days else f"منذ {years} سنة"
        elif days >= 30:
            months = days // 30
            remaining_days = days % 30
            return f"منذ {months} شهر و{remaining_days} يوم" if remaining_days else f"منذ {months} شهر"
        elif days >= 1:
            return f"منذ {days} يوم"
        elif hours >= 1:
            return f"منذ {hours} ساعة و{minutes} دقيقة" if minutes else f"منذ {hours} ساعة"
        elif minutes >= 1:
            return f"منذ {minutes} دقيقة"
        else:
            return "منذ أقل من دقيقة"

    requests = []
    for row in rows:
        requests.append({
            "identifier": row[0],
            "note": row[1],
            "payment_proof_path": row[2],
            "time_ago": time_ago(row[3]),
            "name": row[4] or 'غير معروف',
            "phone": row[5] or row[0]
        })

    return render_template('admin_upgrade_requests.html', requests=requests, new_requests_count=new_requests_count)
def get_pending_upgrade_requests_count():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM pending_payments")
    count = cursor.fetchone()[0]
    conn.close()
    return count    
    
    
@app.route('/admin/reject_upgrade', methods=['POST'])
def reject_upgrade():
    identifier = request.form['identifier']
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM pending_payments WHERE identifier = ?', (identifier,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_upgrade_requests'))    
    
@app.route('/admin/upgraded_users')
def upgraded_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, phone, email, upgrade_date, upgrade_duration_days
        FROM users
        WHERE is_upgraded = 1 AND upgrade_date IS NOT NULL
    ''')
    rows = cursor.fetchall()
    conn.close()

    users = []
    for row in rows:
        users.append({
            'id': row[0],
            'name': row[1],
            'phone': row[2],
            'email': row[3],
            'upgrade_date': row[4],
            'duration': row[5]
        })

    return render_template('admin_upgraded_users.html', users=users)   
    
@app.route('/admin/remove_upgrade', methods=['POST'])
def remove_upgrade():
    user_id = request.form['user_id']

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET is_upgraded = 0,
            upgrade_date = NULL,
            upgrade_duration_days = 0,
            upgrade_code = NULL
        WHERE id = ?
    ''', (user_id,))
    conn.commit()
    conn.close()

    flash("✅ تم حذف الترقية بنجاح", "success")
    return redirect(url_for('upgraded_users'))   
from flask import request, redirect, url_for, flash
from datetime import datetime
import sqlite3

@app.route('/admin/accept_upgrade', methods=['POST'])
def accept_upgrade():
    identifier = request.form['identifier']
    duration_type = request.form.get('duration_type')
    
    # تحديد عدد الأيام حسب الاختيار
    if duration_type == 'month':
        days = 30
    elif duration_type == 'year':
        days = 365
    elif duration_type == 'custom':
        try:
            days = int(request.form.get('custom_days', 0))
            if days <= 0:
                raise ValueError
        except ValueError:
            flash("⚠️ المدة المخصصة غير صالحة.", "warning")
            return redirect(url_for('admin_upgrade_requests'))
    else:
        flash("⚠️ يرجى اختيار مدة الترقية.", "warning")
        return redirect(url_for('admin_upgrade_requests'))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # تأكد من أن المستخدم موجود
    cursor.execute("SELECT id FROM users WHERE email = ? OR phone = ?", (identifier, identifier))
    user = cursor.fetchone()
    if not user:
        conn.close()
        flash("❌ المستخدم غير موجود", "error")
        return redirect(url_for('admin_upgrade_requests'))

    upgrade_date = datetime.now().strftime('%Y-%m-%d')

    # تحديث حالة المستخدم
    cursor.execute('''
        UPDATE users
        SET is_upgraded = 1,
            upgrade_date = ?,
            upgrade_duration_days = ?
        WHERE email = ? OR phone = ?
    ''', (upgrade_date, days, identifier, identifier))

    # حذف من جدول pending_payments بعد القبول
    cursor.execute("DELETE FROM pending_payments WHERE identifier = ?", (identifier,))

    conn.commit()
    conn.close()

    flash("✅ تم قبول الترقية", "success")
    return redirect(url_for('admin_upgrade_requests'))


# --------------------------------------
# صفحة إرسال معلومات الدفع عبر Baridimob
# --------------------------------------
@app.route('/baridimob-upgrade', methods=['GET', 'POST'])
def baridimob_upgrade():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # تستقبل بيانات المستخدم والصورة هنا
        flash("✅ تم استلام معلومات الدفع بنجاح. سيتم التحقق قريباً.", "success")
        return redirect(url_for('baridimob_upgrade'))

    return render_template('baridimob_upgrade.html')
    
# --------------------------------------
# صفحة مشاهدة إعلان للترقية
# --------------------------------------





@app.route('/watch-ad', methods=['GET', 'POST'])
def watch_ad():
    if 'email' not in session:
        return redirect(url_for('login'))

    user_email = session['email']
    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # التحقق من الترقية الحالية
    cursor.execute('''
        SELECT id, expires_at FROM ad_views
        WHERE user_email = ? AND is_active = 1
    ''', (user_email,))
    active_row = cursor.fetchone()

    if active_row:
        ad_id, expires_at_str = active_row
        expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
        if datetime.now() >= expires_at:
            # انتهت الترقية – إلغاءها
            cursor.execute('UPDATE ad_views SET is_active = 0 WHERE id = ?', (ad_id,))
            conn.commit()
        else:
            remaining = (expires_at - datetime.now()).seconds // 60
            flash(f"⏳ لديك ترقية مؤقتة فعالة، تنتهي بعد {remaining} دقيقة", "info")
            conn.close()
            return render_template('watch_ad.html', already_upgraded=True)

    # حساب عدد المشاهدات لهذا اليوم
    cursor.execute('''
        SELECT COUNT(*) FROM ad_views
        WHERE user_email = ? AND watched_at >= ?
    ''', (user_email, today_start.strftime("%Y-%m-%d %H:%M:%S")))
    views_today = cursor.fetchone()[0]

    if request.method == 'POST':
        if views_today >= 2:
            flash("❌ لقد شاهدت الحد الأقصى من الإعلانات المسموح به اليوم (2 مرات).", "warning")
            conn.close()
            return redirect(url_for('watch_ad'))

        expires = now + timedelta(hours=1)
        cursor.execute('''
            INSERT INTO ad_views (user_email, watched_at, expires_at, is_active)
            VALUES (?, ?, ?, 1)
        ''', (user_email, now.strftime("%Y-%m-%d %H:%M:%S"), expires.strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        flash("🎉 تم منحك ترقية مؤقتة لمدة ساعة!", "success")
        return redirect(url_for('profile'))

    conn.close()
    return render_template('watch_ad.html', already_upgraded=False)
from flask import request, render_template, redirect, url_for, flash
from datetime import datetime, timedelta
@app.route('/admin/grant_upgrade_custom', methods=['GET', 'POST'])
def grant_upgrade_custom():
    if 'role' not in session or session['role'] != 'admin':
        flash("🚫 غير مسموح", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        try:
            duration_days = int(request.form.get('duration', 1))
        except ValueError:
            flash("❌ مدة الترقية غير صالحة", "danger")
            return redirect(url_for('grant_upgrade_custom'))

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expires = now + timedelta(days=duration_days)

        # ✅ جلب جميع المستخدمين الغير مرفقين أو لي انتهت ترقيتهم (حتى admin/editor)
        sql = '''
        SELECT id, email FROM users
        WHERE (is_upgraded = 0 OR datetime(upgrade_date, '+' || upgrade_duration_days || ' days') < ?)
        '''
        cursor.execute(sql, (now_str,))
        users = cursor.fetchall()

        for user_id, email in users:
            # تحديث جدول المستخدمين
            # تحديث جدول المستخدمين
            cursor.execute('''
                UPDATE users SET
                    is_upgraded = 1,
                    upgrade_date = ?,
                    upgrade_duration_days = ?,
                    upgrade_code = '🔑 ترقية مخصصة'
                WHERE id = ?
            ''', (now_str, duration_days, user_id))
            # تسجيل صلاحية مشاهدة الإعلانات
            cursor.execute('''
                INSERT INTO ad_views (user_email, watched_at, expires_at, is_active)
                VALUES (?, ?, ?, 1)
            ''', (email, now_str, expires.strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        conn.close()

        flash(f"✅ تم ترقية {len(users)} مستخدم لمدة {duration_days} يوم!", "success")
        return redirect(url_for('grant_upgrade_custom'))

    return render_template('admin_grant_upgrade.html')
    
@app.route('/admin/remove_custom_upgrades', methods=['POST'])
def remove_custom_upgrades():
    if 'role' not in session or session['role'] != 'admin':
        flash("🚫 غير مسموح", "danger")
        return redirect(url_for('home'))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # جلب المستخدمين لي عندهم ترقية مخصصة (من هذا الكود فقط)
    cursor.execute('''
        SELECT id, email FROM users
        WHERE is_upgraded = 1 AND upgrade_code = '🔑 ترقية مخصصة'
    ''')
    users = cursor.fetchall()

    for user_id, email in users:
        # نزع الترقية
        cursor.execute('''
            UPDATE users
            SET is_upgraded = 0,
                upgrade_date = NULL,
                upgrade_duration_days = 0,
                upgrade_code = NULL
            WHERE id = ?
        ''', (user_id,))

        # نزع الصلاحيات من ad_views
        cursor.execute('''
            UPDATE ad_views
            SET is_active = 0
            WHERE user_email = ? AND is_active = 1
        ''', (email,))

    conn.commit()
    conn.close()

    flash(f"❌ تم نزع الترقية من {len(users)} مستخدم من الترقيات المخصصة.", "warning")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT name, email, upgrade_date, upgrade_duration_days
        FROM users
        WHERE is_upgraded = 1 AND upgrade_code = '🔑 ترقية مخصصة'
        ORDER BY upgrade_date DESC
    ''')
    upgraded_users = cursor.fetchall()
    conn.close()

    return render_template('admin_grant_upgrade.html', upgraded_users=upgraded_users)
    return redirect(url_for('grant_upgrade_custom'))
# --------------------------------------
# صفحة فريق الدعم والمحررين
# --------------------------------------
@app.route('/support-team')
def support_team():
    if 'email' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT name, phone, email, role FROM users WHERE role IN ("admin", "editor")')
    non_user_roles = [
        {'name': row[0], 'phone': row[1], 'email': row[2], 'role': row[3]}
        for row in cursor.fetchall()
    ]
    conn.close()

    return render_template('support_team.html', non_user_roles=non_user_roles)

# --------------------------------------
# صفحة إدخال كود الترقية
# --------------------------------------
@app.route('/enter-upgrade-code', methods=['GET', 'POST'])
def enter_upgrade_code():
    if 'email' not in session:
        return redirect(url_for('login'))

    message = None
    message_type = None

    if request.method == 'POST':
        user_email = session['email']
        code = request.form.get('code')

        success, response = apply_upgrade(user_email, code)

        if success:
            flash(response, "success")
        else:
            flash(response, "error")

        return redirect(url_for('enter_upgrade_code'))

    return render_template('enter_upgrade_code.html')

from flask import render_template, session, redirect, url_for
from datetime import datetime, timedelta
import sqlite3

from math import ceil  # ✅ أضف هذا في بداية الملف إذا لم يكن موجوداً

@app.route('/upgrade_status')
def upgrade_status():
    if 'email' not in session:
        return redirect(url_for('login'))

    user_email = session['email']

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # جلب بيانات المستخدم
    cursor.execute("SELECT phone, upgrade_date, upgrade_duration_days, is_upgraded FROM users WHERE email = ?", (user_email,))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return "❌ المستخدم غير موجود"

    user_phone, upgrade_date, duration, is_upgraded = result

    # جلب طلب الترقية إن وُجد
    cursor.execute('''
        SELECT note, payment_proof_path, created_at
        FROM pending_payments
        WHERE identifier = ? OR identifier = ?
        ORDER BY created_at DESC
        LIMIT 1
    ''', (user_email, user_phone))
    payment = cursor.fetchone()

    # ✅ التوجيه مباشرة إذا لا يوجد ترقية ولا طلب
    if not upgrade_date and not is_upgraded and not payment:
        conn.close()
        return redirect(url_for('upgrade_page'))

    # حساب الحالة
    status = "قيد الانتظار"
    days_left = None

    if upgrade_date and duration and is_upgraded:
        try:
            dt = datetime.strptime(upgrade_date, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                dt = datetime.strptime(upgrade_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                dt = datetime.strptime(upgrade_date, "%Y-%m-%d")

        delta = (dt + timedelta(days=duration)) - datetime.now()
        days_left = max(0, ceil(delta.total_seconds() / 86400))  # ✅ أدق حساب

        status = "مفعل" if delta.total_seconds() > 0 else "منتهي"

    # تجهيز معلومات الطلب
    payment_info = None
    non_user_roles = []

    if payment:
        note, image_path, created_at = payment
        payment_info = {
            "note": note,
            "image_path": image_path,
            "created_at": created_at
        }

        # جلب المحررين/الإداريين فقط إذا كان فيه طلب
        cursor.execute('SELECT name, phone, email, role FROM users WHERE role IN ("admin", "editor")')
        non_user_roles = [
            {'name': row[0], 'phone': row[1], 'email': row[2], 'role': row[3]}
            for row in cursor.fetchall()
        ]

    conn.close()

    return render_template('upgrade_status.html',
                           status=status,
                           days_left=days_left,
                           payment_info=payment_info,
                           non_user_roles=non_user_roles)



@app.route('/report_rating', methods=['POST'])
def report_rating():
    if 'phone' not in session:
        return redirect(url_for('login'))

    rating_id = request.form.get('rating_id')
    phone = session['phone']
    next_url = request.form.get('next_url') or url_for('home')

    if not rating_id or not rating_id.isdigit():
        flash("❌ معرف التقييم غير صالح.")
        return redirect(next_url)

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT id FROM users WHERE phone = ?', (phone,))
        result = cursor.fetchone()
        if not result:
            flash("❌ المستخدم غير موجود.")
            return redirect(next_url)

        user_id = result[0]

        cursor.execute('SELECT 1 FROM ratings WHERE id = ?', (rating_id,))
        if not cursor.fetchone():
            flash("❌ التقييم غير موجود.")
            return redirect(next_url)

        cursor.execute('SELECT 1 FROM rating_reports WHERE rating_id = ? AND user_id = ?', (rating_id, user_id))
        if cursor.fetchone():
            flash("⚠️ لقد أبلغت عن هذا التقييم من قبل.")
        else:
            cursor.execute('INSERT INTO rating_reports (rating_id, user_id) VALUES (?, ?)', (rating_id, user_id))
            cursor.execute('SELECT COUNT(*) FROM rating_reports WHERE rating_id = ?', (rating_id,))
            report_count = cursor.fetchone()[0]

            if report_count >= 10:
                cursor.execute('DELETE FROM ratings WHERE id = ?', (rating_id,))
                flash("✅ تم حذف التقييم تلقائيًا بعد 10 بلاغات.")
            else:
                flash("🚨 تم الإبلاغ عن التقييم. شكراً لمساهمتك.")

            conn.commit()

    except Exception as e:
        conn.rollback()
        flash(f"❌ حدث خطأ: {str(e)}")
    finally:
        conn.close()

    return redirect(next_url)

@app.route('/admin/reported_ratings')
def reported_ratings():
    if session.get('role') not in ['admin', 'editor']:
        return redirect(url_for('home'))

    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # جلب التقييمات المبلغ عنها
    cursor.execute('''
        SELECT 
            r.id,
            r.rating,
            r.comment,
            r.date_rated,
            r.worker_id,
            r.customer_id,
            uw.name AS worker_name,
            uc.name AS customer_name,
            COUNT(rr.id) AS report_count
        FROM rating_reports rr
        JOIN ratings r ON rr.rating_id = r.id
        JOIN users uw ON r.worker_id = uw.id
        JOIN users uc ON r.customer_id = uc.id
        GROUP BY rr.rating_id
        ORDER BY report_count DESC, r.date_rated DESC
    ''')
    reported = cursor.fetchall()
    conn.close()

    return render_template('admin/reported_ratings.html', reported=reported)
@app.route('/block_user', methods=['POST'])
def block_user():
    if session.get('role') != 'admin':
        return "🚫 غير مصرح", 403

    user_id = request.form.get('user_id')
    reason = request.form.get('reason', '')

# ✅ إذا اختار "أخرى" يتم استخدام الحقل اليدوي
    if reason == 'أخرى':
        reason = request.form.get('custom_reason', '').strip()

    blocked_by = session.get('phone') or session.get('email') or 'admin'

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # التحقق إذا كان المستخدم Superadmin
    cursor.execute("SELECT is_superadmin FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()

    if result and result[0] == 1:
        # إلغاء الحظر تلقائيًا إذا حاولنا حظر الأدمن الرئيسي
        cursor.execute("DELETE FROM block WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        flash("🚫 لا يمكن حظر الأدمن الرئيسي. تم إلغاء الحظر تلقائيًا.", "warning")
        return redirect(request.referrer or url_for('home'))

    # تنفيذ الحظر للمستخدم العادي
    cursor.execute("INSERT OR IGNORE INTO block (user_id, reason, blocked_by) VALUES (?, ?, ?)",
                   (user_id, reason, blocked_by))
    conn.commit()
    conn.close()

    flash("✅ تم حظر المستخدم.", "success")
    return redirect(request.referrer or url_for('home'))
@app.route('/unblock_user', methods=['POST'])
def unblock_user():
    if session.get('role') != 'admin':
        return "🚫 غير مصرح", 403

    user_id = request.form.get('user_id')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # تحقق إذا كان المستخدم المراد إلغاء حظره هو superadmin
    cursor.execute("SELECT is_superadmin FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()

    if row and row[0] == 1:
        # إلغاء الحظر تلقائيًا إذا كان superadmin
        cursor.execute("DELETE FROM block WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        flash("✅ تم إلغاء الحظر عن الأدمن الرئيسي تلقائيًا.", "success")
        return redirect(request.referrer or url_for('home'))

    # إلغاء الحظر العادي
    cursor.execute("DELETE FROM block WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    flash("✅ تم إلغاء الحظر.", "success")
    return redirect(request.referrer or url_for('home'))
    
@app.before_request
def check_block_status():
    if 'phone' in session:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT id, role, is_superadmin FROM users WHERE phone = ?", (session['phone'],))
        user = cursor.fetchone()

        if user:
            user_id, real_role, is_superadmin = user

            # 🛡️ حماية الأدمن الرئيسي من الحظر
            if is_superadmin == 1:
                cursor.execute("DELETE FROM block WHERE user_id = ?", (user_id,))
                conn.commit()
            else:
                # 🚫 تحقق من الحظر
                cursor.execute("SELECT 1 FROM block WHERE user_id = ?", (user_id,))
                if cursor.fetchone():
                    conn.close()
                    session.clear()
                    flash("🚫 تم حظرك من استخدام التطبيق.", "error")
                    return redirect(url_for('login'))

            # 🔐 تحقق من تطابق الدور الحقيقي مع دور الجلسة
            if session.get("role") != real_role:
                conn.close()
                session.clear()
                flash("⚠️ تم تغيير صلاحياتك. الرجاء تسجيل الدخول مجددًا.", "warning")
                return redirect(url_for('login'))

        conn.close()
if __name__ == "__main__":
    app.run()