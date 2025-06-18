import sqlite3
import os

# التأكد من وجود مجلد قاعدة البيانات
os.makedirs('database', exist_ok=True)

# الاتصال بقاعدة البيانات (سيتم إنشاؤها إذا لم تكن موجودة)
conn = sqlite3.connect('database/db.sqlite')
cursor = conn.cursor()

# إنشاء جدول users
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    wilaya TEXT NOT NULL,
    baladiya TEXT,
    service_type TEXT NOT NULL,
    description TEXT,
    image_path TEXT,
    is_available INTEGER DEFAULT 0 CHECK(is_available IN (0, 1)),
    date_registered DATETIME DEFAULT CURRENT_TIMESTAMP,
    verification_token TEXT,
    reset_token TEXT,
    is_verified INTEGER DEFAULT 0 CHECK(is_verified IN (0, 1)),

    -- ✅ الجنس
    gender TEXT DEFAULT 'غير محدد' CHECK(gender IN ('ذكر', 'أنثى', 'غير محدد')),

    -- ✅ عرض رقم الهاتف
    show_phone INTEGER DEFAULT 1 CHECK(show_phone IN (0, 1)),

    -- خصائص الترقية
    is_upgraded INTEGER DEFAULT 0 CHECK(is_upgraded IN (0, 1)),
    upgrade_date DATETIME,
    upgrade_duration_days INTEGER DEFAULT 0,
    upgrade_code TEXT,
    is_banned INTEGER DEFAULT 0 CHECK(is_banned IN (0, 1)),

    -- صلاحية الوصول
    role TEXT DEFAULT 'user' CHECK(role IN ('admin', 'editor', 'user')),

    -- مفتاح تسجيل الدخول الخاص بالأدمن
    admin_login_key TEXT
)
''')

# ✅ إضافة عمود is_superadmin بطريقة آمنة
try:
    cursor.execute('''
      ALTER TABLE users ADD COLUMN is_superadmin INTEGER DEFAULT 0 CHECK(is_superadmin IN (0, 1))
    ''')
    print("✅ تم إضافة عمود is_superadmin.")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e).lower():
        print("ℹ️ العمود is_superadmin موجود مسبقًا، لم يتم التعديل.")
    else:
        raise

# إنشاء جدول أكواد الترقية
cursor.execute('''
CREATE TABLE IF NOT EXISTS upgrade_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    used INTEGER DEFAULT 0 CHECK(used IN (0, 1)),
    assigned_to TEXT,  -- email أو phone
    date_generated DATETIME DEFAULT CURRENT_TIMESTAMP,
    date_used DATETIME
)
''')

# إنشاء جدول التقييمات
cursor.execute('''
CREATE TABLE IF NOT EXISTS ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id INTEGER NOT NULL,
    customer_id INTEGER NOT NULL,
    rating INTEGER CHECK(rating BETWEEN 1 AND 5),
    comment TEXT,
    date_rated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (worker_id) REFERENCES users(id),
    FOREIGN KEY (customer_id) REFERENCES users(id)
)
''')

# ✅ إنشاء جدول بلاغات التقييمات
cursor.execute('''
CREATE TABLE IF NOT EXISTS rating_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rating_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    report_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(rating_id, user_id),
    FOREIGN KEY (rating_id) REFERENCES ratings(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# إنشاء جدول الرسائل
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    date_sent DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER DEFAULT 0 CHECK(is_read IN (0, 1))
)
''')

# إنشاء جدول طلبات الصداقة
cursor.execute('''
CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    date_sent DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# إنشاء جدول الأصدقاء
cursor.execute('''
CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, friend_id)
)
''')

# فهرس فريد إضافي لتسريع التحقق من الصداقات
cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS unique_friendship ON friends(user_id, friend_id)')

# ✅ إنشاء جدول الدفع مع رقم التحويل والصورة
cursor.execute('''
CREATE TABLE IF NOT EXISTS pending_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    transaction_number TEXT,
    note TEXT,
    payment_proof_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')

# ✅ إنشاء جدول مشاهدات الإعلانات
cursor.execute('''
CREATE TABLE IF NOT EXISTS ad_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    watched_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    is_active INTEGER DEFAULT 1 CHECK(is_active IN (0, 1))
)
''')

# ✅ إنشاء جدول الحظر
cursor.execute('''
CREATE TABLE IF NOT EXISTS block (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    reason TEXT,
    blocked_by TEXT,  -- رقم الهاتف أو البريد أو الاسم
    date_blocked DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()

print("✅ تم إنشاء جميع الجداول بنجاح، مع إضافة عمود is_superadmin لحماية الأدمن الرئيسي! 👑🛡️")