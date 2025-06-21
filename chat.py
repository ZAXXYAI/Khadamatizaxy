from flask import Blueprint, request, redirect, session, render_template, url_for, jsonify
import sqlite3
from datetime import datetime, timedelta
# إنشاء Blueprint باسم 'chat'
chat_bp = Blueprint('chat', __name__)




def get_user_id_by_session():
    phone = session.get('phone')
    if not phone:
        return None
    return get_user_id_by_phone(phone)



# استرجاع اسم المستخدم وصورته من ID
def get_user_name(user_id):
    # إذا كان البوت
    if user_id == 0:
        return {
            'name': 'البوت',
            'profile_picture': 'bot.ico'
        }

    # المستخدم الحقيقي
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT name, image_path FROM users WHERE id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        image_filename = result[1] if result[1] else 'default.jpg'
        return {
            'name': result[0],
            'profile_picture': image_filename
        }
    else:
        return {
            'name': 'غير معروف',
            'profile_picture': 'default.jpg'
        }




typing_status = {}  # (sender_id, receiver_id): last_typing_time

# المستخدم بدأ الكتابة
@chat_bp.route('/typing/<int:receiver_id>', methods=['POST'])
def typing(receiver_id):
    user_id = get_user_id_by_session()
    if user_id:
        typing_status[(user_id, receiver_id)] = datetime.now()
    return '', 204

# المستخدم توقف عن الكتابة
@chat_bp.route('/stop_typing/<int:receiver_id>', methods=['POST'])
def stop_typing(receiver_id):
    user_id = get_user_id_by_session()
    if user_id:
        typing_status.pop((user_id, receiver_id), None)
    return '', 204

# الطرف الآخر يكتب الآن؟
@chat_bp.route('/check_typing/<int:receiver_id>')
def check_typing(receiver_id):
    user_id = get_user_id_by_session()
    if not user_id:
        return jsonify({'is_typing': False})

    # نحذف الحالات التي مر عليها أكثر من 5 ثوانٍ
    expired = []
    now = datetime.now()
    for key, ts in typing_status.items():
        if now - ts > timedelta(seconds=12):
            expired.append(key)
    for key in expired:
        typing_status.pop(key)

    # نتحقق: هل الشخص الذي تراسله يكتب لك الآن؟
    last_typing_time = typing_status.get((receiver_id, user_id))
    if last_typing_time and (now - last_typing_time < timedelta(seconds=5)):
        return jsonify({'is_typing': True})
    else:
        return jsonify({'is_typing': False})




# استرجاع ID المستخدم من رقم الهاتف
def get_user_id_by_phone(phone):
    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE phone = ?', (phone,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# عرض صفحة المحادثة بين مستخدمين
@chat_bp.route('/<int:receiver_id>')
def chat(receiver_id):
    if 'phone' not in session:
        return redirect(url_for('login'))

    sender_phone = session['phone']
    sender_id = get_user_id_by_phone(sender_phone)
    if not sender_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database/db.sqlite')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE messages
        SET is_read = 1
        WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
    ''', (receiver_id, sender_id))
    conn.commit()

    cursor.execute('''
        SELECT messages.*, users.name AS sender_name, users.image_path AS sender_image
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY date_sent
    ''', (sender_id, receiver_id, receiver_id, sender_id))
    messages_data = cursor.fetchall()

    # جلب اسم وصورة المستقبل
    cursor.execute('SELECT name, image_path FROM users WHERE id = ?', (receiver_id,))
    receiver_row = cursor.fetchone()
    conn.close()

    messages = []
    for row in messages_data:
        message = {
            'sender_name': row['sender_name'],
            'message': row['message'],
            'date_sent': row['date_sent'],
            'sender_id': row['sender_id'],
            'is_read': row['is_read'],
            'sender_image_url': get_profile_picture(row['sender_image'])
        }
        messages.append(message)

    return render_template('chat.html',
        messages=messages,
        receiver_id=receiver_id,
        receiver_name=receiver_row['name'],
        receiver_picture=get_profile_picture(receiver_row['image_path']),
        user_id=sender_id
    )
    
@chat_bp.route('/send_message', methods=['POST'])
def send_message():
    if 'phone' not in session:
        return redirect(url_for('login'))

    sender_phone = session['phone']
    sender_id = get_user_id_by_phone(sender_phone)
    if not sender_id:
        return redirect(url_for('login'))

    receiver_id = request.form['receiver_id']
    message = request.form['message']

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, message)
        VALUES (?, ?, ?)
    ''', (sender_id, receiver_id, message))
    conn.commit()
    conn.close()

    return redirect(url_for('chat.chat', receiver_id=receiver_id))

# عرض كل المحادثات السابقة للمستخدم
@chat_bp.route('/conversations')
def conversations():
    if 'phone' not in session:
        return redirect(url_for('login'))

    user_phone = session['phone']
    user_id = get_user_id_by_phone(user_phone)
    if not user_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database/db.sqlite')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT DISTINCT 
            CASE 
                WHEN sender_id = ? THEN receiver_id 
                ELSE sender_id 
            END AS contact_id
        FROM messages
        WHERE sender_id = ? OR receiver_id = ?
    ''', (user_id, user_id, user_id))
    conversations_data = cursor.fetchall()

    conversations = []
    for row in conversations_data:
        contact_id = row[0]
        if contact_id is None:
            continue
        contact_info = get_user_name(contact_id)

        # حساب عدد الرسائل غير المقروءة من هذا الشخص
        cursor.execute('''
            SELECT COUNT(*) FROM messages
            WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
        ''', (contact_id, user_id))
        unread_count = cursor.fetchone()[0]

        conversations.append({
            'id': contact_id,
            'name': contact_info['name'],
            'profile_picture': contact_info['profile_picture'],
            'unread_count': unread_count
        })

    conn.close()
    return render_template('conversations.html', conversations=conversations)

# دالة مساعدة للوصول إلى الصور
def get_profile_picture(filename):
    if not filename:
        return url_for('static', filename='uploads/default.jpg')
    
    # إذا كانت الصورة فيها 'uploads/' بالفعل، نحذفها باش ما نكرروهاش
    clean_filename = filename.replace('uploads/', '').replace('/static/', '')
    return url_for('static', filename=f'uploads/{clean_filename}')