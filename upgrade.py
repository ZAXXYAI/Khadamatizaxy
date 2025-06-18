import sqlite3
from datetime import datetime
from datetime import datetime, timedelta

DB_PATH = 'database/db.sqlite'

# 🔐 التحقق من صلاحية كود الترقية
def is_valid_upgrade_code(code):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT used, assigned_to FROM upgrade_codes WHERE code = ?", (code,))
    result = cursor.fetchone()
    conn.close()

    if result is None:
        return False, "الكود غير موجود"
    elif result[0] == 1:
        return False, "❌ الكود مستعمل"
    else:
        return True, result[1]  # valid, assigned_to

# ✅ ترقية مستخدم باستخدام كود صالح
def apply_upgrade(user_email, code, duration_days=30):
    # تحقق إذا كان المستخدم محظور
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT is_banned FROM users WHERE email = ?", (user_email,))
    result = cursor.fetchone()

    if result and result[0] == 1:
        conn.close()
        return False, "🚫 تم حظرك من استعمال الأكواد."

    # التحقق من صلاحية الكود
    is_valid, assigned_to = is_valid_upgrade_code(code)
    if not is_valid:
        return False, assigned_to  # الرسالة موجودة في is_valid_upgrade_code

    if assigned_to and assigned_to != user_email:
        return False, "⛔ هذا الكود مخصص لمستخدم آخر. يرجى التأكد من الكود أو الاتصال بالدعم."

    # تحديث المستخدم وترقية الحساب
    now = datetime.now()
    cursor.execute('''
        UPDATE users
        SET is_upgraded = 1,
            upgrade_date = ?,
            upgrade_duration_days = ?,
            upgrade_code = ?
        WHERE email = ?
    ''', (now, duration_days, code, user_email))

    # تعليم الكود كمستعمل
    cursor.execute('''
        UPDATE upgrade_codes
        SET used = 1,
            assigned_to = ?,
            date_used = ?
        WHERE code = ?
    ''', (user_email, now, code))

    conn.commit()
    conn.close()
    return True, "✅ تمت الترقية بنجاح"
# 🚫 حظر مستخدم من استخدام الكودات مستقبلاً
def ban_user_from_upgrade(user_email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET is_upgraded = 0,
            upgrade_code = NULL,
            upgrade_date = NULL,
            upgrade_duration_days = 0,
            is_banned = 1
        WHERE email = ?
    ''', (user_email,))
    conn.commit()
    conn.close()
    return True, "🚫 تم حظر المستخدم من الترقية"

# 🔄 إعادة تفعيل إمكانية الترقية بعد الحظر
def unban_user(user_email):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users
        SET is_banned = 0
        WHERE email = ?
    ''', (user_email,))
    conn.commit()
    conn.close()
    return True, "✅ تم رفع الحظر عن المستخدم"

# 📃 عرض جميع الأكواد (معدّلة لتتوافق مع ترتيب الأعمدة)
from datetime import datetime, timedelta
import sqlite3

def parse_any_datetime(date_str):
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unknown datetime format: {date_str}")

def get_all_upgrade_codes():
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            uc.code,             -- 0
            uc.assigned_to,      -- 1
            uc.used,             -- 2
            u.upgrade_date,      -- 3
            u.upgrade_duration_days  -- 4
        FROM upgrade_codes uc
        LEFT JOIN users u ON uc.assigned_to = u.email
    ''')

    codes = []
    for code, assigned_to, used, upgrade_date, duration in cursor.fetchall():
        if used and upgrade_date and duration:
            try:
                upgrade_dt = parse_any_datetime(upgrade_date)
                end_dt = upgrade_dt + timedelta(days=duration)
                remaining = (end_dt - datetime.utcnow()).days
            except Exception:
                remaining = None
        else:
            remaining = None

        codes.append((code, assigned_to, used, remaining))

    conn.close()
    return codes
def add_upgrade_code(code, assigned_to=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO upgrade_codes (code, assigned_to)
            VALUES (?, ?)
        ''', (code, assigned_to))
        conn.commit()
        return True, "✅ تم إضافة الكود"
    except sqlite3.IntegrityError:
        return False, "⚠️ الكود موجود مسبقًا"
    finally:
        conn.close()
from datetime import datetime, timedelta

def get_upgrade_durations():
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT name, email, upgrade_date, upgrade_duration_days
        FROM users
        WHERE is_upgraded = 1
    ''')

    results = []
    for name, email, upgrade_date_str, duration in cursor.fetchall():
        if upgrade_date_str and duration:
            try:
                upgrade_dt = datetime.strptime(upgrade_date_str, "%Y-%m-%d")
                end_dt = upgrade_dt + timedelta(days=duration)
                remaining = (end_dt - datetime.utcnow()).days
            except Exception:
                remaining = None
        else:
            remaining = None
        
        results.append((name, email, upgrade_date_str, remaining))
    
    conn.close()
    return results
# ❌ حذف كود ترقية
def delete_upgrade_code(code):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM upgrade_codes WHERE code = ?", (code,))
    conn.commit()
    conn.close()
    return True, "🗑️ تم حذف الكود"

# 👥 المستخدمون الذين استعملوا الأكواد
def get_upgraded_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT name, email, phone, upgrade_code, upgrade_date, upgrade_duration_days
        FROM users
        WHERE is_upgraded = 1 AND upgrade_code IS NOT NULL
    ''')

    users = []
    for name, email, phone, code, upgrade_date_str, duration in cursor.fetchall():
        if upgrade_date_str and duration:
            try:
                upgrade_dt = datetime.strptime(upgrade_date_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                upgrade_dt = datetime.strptime(upgrade_date_str, "%Y-%m-%d %H:%M:%S")
            remaining_days = (upgrade_dt + timedelta(days=duration) - datetime.utcnow()).days
        else:
            remaining_days = None

        users.append((name, email, phone, code, remaining_days))

    conn.close()
    return users


def get_active_upgraded_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    today = datetime.now()

    cursor.execute('''
        SELECT name, email, phone, upgrade_code, upgrade_date, upgrade_duration_days
        FROM users
        WHERE is_upgraded = 1 AND upgrade_date IS NOT NULL
    ''')

    results = []
    for row in cursor.fetchall():
        try:
            upgrade_date = datetime.strptime(row[4], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            upgrade_date = datetime.strptime(row[4], "%Y-%m-%d %H:%M:%S")

        duration_days = row[5]
        expiry_date = upgrade_date + timedelta(days=duration_days)

        if today <= expiry_date:
            remaining_days = (expiry_date - today).days
            results.append({
                'name': row[0],
                'email': row[1],
                'phone': row[2],
                'code': row[3],
                'days_remaining': remaining_days
            })

    conn.close()
    return results
def manually_upgrade_user(identifier, duration_days):
    if not identifier:
        return False, "⚠️ المرجو إدخال بريد إلكتروني أو رقم هاتف."

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # البحث عن المستخدم بالبريد أو الهاتف
    cursor.execute("""
        SELECT id, upgrade_date, upgrade_duration_days, email, phone
        FROM users
        WHERE email = ? OR phone = ?
    """, (identifier, identifier))

    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, f"❌ المستخدم غير مسجل في قاعدة البيانات: {identifier}"

    _, upgrade_date_str, upgrade_duration, email, phone = user

    # التحقق من صلاحية الترقية القديمة
    if upgrade_date_str:
        try:
            upgrade_date = datetime.strptime(upgrade_date_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            upgrade_date = datetime.strptime(upgrade_date_str, "%Y-%m-%d %H:%M:%S")

        expiry_date = upgrade_date + timedelta(days=upgrade_duration or 0)

        if datetime.now() <= expiry_date:
            conn.close()
            return False, f"⚠️ المستخدم لديه ترقية صالحة تنتهي في {expiry_date.date()}"

    # تنفيذ الترقية الجديدة
    new_upgrade_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    cursor.execute("""
        UPDATE users
        SET is_upgraded = 1,
            upgrade_code = NULL,
            upgrade_date = ?,
            upgrade_duration_days = ?
        WHERE email = ? OR phone = ?
    """, (new_upgrade_date, duration_days, identifier, identifier))

    conn.commit()
    conn.close()

    method = "📧 " + email if identifier == email else "📱 " + phone
    return True, f"✅ تم ترقية {method} لمدة {duration_days} يومًا"
def get_manual_upgraded_users():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, name, email, phone, upgrade_duration_days,
               ROUND((julianday(upgrade_date) + upgrade_duration_days) - julianday('now')) AS days_remaining
        FROM users
        WHERE is_upgraded = 1 AND upgrade_code IS NULL
        ORDER BY days_remaining DESC
    """)

    users = cursor.fetchall()
    conn.close()

    result = []
    for u in users:
        result.append({
            "id": u[0],
            "name": u[1],
            "email": u[2],
            "phone": u[3],
            "duration": u[4],
            "days_remaining": max(u[5], 0)
        })

    return result