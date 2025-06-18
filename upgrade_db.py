import sqlite3

def table_exists(cursor, table_name):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None

def add_missing_columns(cursor, table_name, columns_dict):
    if not table_exists(cursor, table_name):
        print(f"❌ جدول {table_name} غير موجود، لم يتم تعديل أي أعمدة.")
        return

    cursor.execute(f"PRAGMA table_info({table_name})")
    existing_columns = [col[1] for col in cursor.fetchall()]

    for col_name, col_type in columns_dict.items():
        if col_name not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                print(f"✅ تم إضافة العمود {col_name} إلى {table_name}")
            except Exception as e:
                print(f"❌ خطأ أثناء إضافة العمود {col_name} إلى {table_name}: {e}")
        else:
            print(f"✔️ العمود {col_name} موجود في {table_name}")

def create_table_if_not_exists(cursor, table_name, create_sql):
    if not table_exists(cursor, table_name):
        try:
            cursor.execute(create_sql)
            print(f"✅ تم إنشاء جدول {table_name}")
        except Exception as e:
            print(f"❌ خطأ أثناء إنشاء جدول {table_name}: {e}")
    else:
        print(f"✔️ جدول {table_name} موجود مسبقاً")

def clean_orphan_rating_reports(cursor):
    print("🧹 جاري تنظيف التبليغات التي لا تملك تقييم...")
    cursor.execute('''
        DELETE FROM rating_reports
        WHERE rating_id NOT IN (SELECT id FROM ratings)
    ''')
    deleted_count = cursor.rowcount
    print(f"✅ تم حذف {deleted_count} تبليغات بدون تقييم.")

def update_all_tables():
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()

    # جداول وتعديلات الأعمدة...
    add_missing_columns(cursor, "users", {
        "is_upgraded": "INTEGER DEFAULT 0 CHECK(is_upgraded IN (0,1))",
        "upgrade_date": "DATETIME",
        "upgrade_duration_days": "INTEGER DEFAULT 0",
        "upgrade_code": "TEXT",
        "is_banned": "INTEGER DEFAULT 0 CHECK(is_banned IN (0,1))",
        "role": "TEXT DEFAULT 'user' CHECK(role IN ('admin','editor','user'))",
        "payment_proof_path": "TEXT",
        "payment_note": "TEXT",
        "gender": "TEXT DEFAULT 'غير محدد' CHECK(gender IN ('ذكر', 'أنثى', 'غير محدد'))",
        "admin_login_key": "TEXT",
        "show_phone": "INTEGER DEFAULT 1 CHECK(show_phone IN (0,1))"
    })

    add_missing_columns(cursor, "pending_payments", {
        "identifier": "TEXT NOT NULL",
        "transaction_number": "TEXT",
        "note": "TEXT",
        "payment_proof_path": "TEXT",
        "created_at": "DATETIME DEFAULT CURRENT_TIMESTAMP"
    })

    add_missing_columns(cursor, "ratings", {
        "worker_id": "INTEGER",
        "customer_id": "INTEGER",
        "rating": "INTEGER",
        "comment": "TEXT",
        "date_rated": "DATETIME DEFAULT CURRENT_TIMESTAMP",
        "reported": "INTEGER DEFAULT 0"
    })

    add_missing_columns(cursor, "upgrade_codes", {
        "code": "TEXT UNIQUE",
        "used": "INTEGER DEFAULT 0 CHECK(used IN (0,1))",
        "assigned_to": "TEXT",
        "date_generated": "DATETIME DEFAULT CURRENT_TIMESTAMP",
        "date_used": "DATETIME"
    })

    add_missing_columns(cursor, "messages", {
        "sender_id": "INTEGER",
        "receiver_id": "INTEGER",
        "message": "TEXT",
        "date_sent": "DATETIME DEFAULT CURRENT_TIMESTAMP",
        "is_read": "INTEGER DEFAULT 0 CHECK(is_read IN (0,1))"
    })

    add_missing_columns(cursor, "friend_requests", {
        "sender_id": "INTEGER",
        "receiver_id": "INTEGER",
        "status": "TEXT DEFAULT 'pending'",
        "date_sent": "DATETIME DEFAULT CURRENT_TIMESTAMP"
    })

    add_missing_columns(cursor, "friends", {
        "user_id": "INTEGER",
        "friend_id": "INTEGER",
        "date_added": "DATETIME DEFAULT CURRENT_TIMESTAMP"
    })

    add_missing_columns(cursor, "ad_views", {
        "user_email": "TEXT NOT NULL",
        "watched_at": "DATETIME NOT NULL",
        "expires_at": "DATETIME NOT NULL",
        "is_active": "INTEGER DEFAULT 1 CHECK(is_active IN (0,1))"
    })

    create_table_if_not_exists(cursor, "rating_reports", '''
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

    create_table_if_not_exists(cursor, "block", '''
        CREATE TABLE IF NOT EXISTS block (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL UNIQUE,
            blocked_by INTEGER,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (blocked_by) REFERENCES users(id)
        )
    ''')

    # 🧹 تنظيف البلاغات اليتيمة
    clean_orphan_rating_reports(cursor)

    conn.commit()
    conn.close()

if __name__ == '__main__':
    update_all_tables()