# update_availability.py
import sqlite3

DB_PATH = 'database/db.sqlite'  # غيره حسب المسار

def update_user_availability():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # تحديث فقط المستخدمين الذين كانوا متاحين وأصبحوا غير متاحين
        cursor.execute("""
            UPDATE users
            SET is_available = 0
            WHERE is_available = 1 AND (
                is_upgraded = 0
                OR (
                    is_upgraded = 1
                    AND upgrade_date IS NOT NULL
                    AND (julianday(upgrade_date) + upgrade_duration_days) < julianday('now')
                )
            )
        """)
        affected_rows = cursor.rowcount  # فقط من تغير فعليًا من متاح إلى غير متاح

        return affected_rows