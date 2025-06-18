# utils/ai_search.py
import requests
import random
import sqlite3
import os

# تحميل المتغيرات من .env لما تكون محلياً (اختياري)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # تخطي إذا ماكانش dotenv موجود، مثلاً في Render




API_KEYS = os.getenv("API_KEYS", "").split(",")

def get_user_data(user_id):
    """
    جلب بيانات مستخدم واحد من قاعدة البيانات.
    """
    conn = sqlite3.connect("database/db.sqlite")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else {}


def get_full_conversation(user_id, limit=10):
    """
    جلب آخر (limit) رسائل بين البوت والمستخدم.
    """
    conn = sqlite3.connect("database/db.sqlite")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        SELECT sender_id, receiver_id, message
        FROM messages
        WHERE sender_id = ? OR receiver_id = ?
        ORDER BY date_sent DESC
        LIMIT ?
        """,
        (user_id, user_id, limit),
    )
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "sender": "أنت" if r["sender_id"] == user_id else "البوت",
            "text": r["message"],
        }
        for r in rows
    ][::-1]  # قلب الترتيب ليكون الأقدم أولًا


# ------------------------- الدالة الرئيسية -------------------------

def send_ai_query(user_id, user_prompt):
    """
    إرسال سؤال المستخدم لنموذج الذكاء الاصطناعي بعد بناء السياق الكامل.
    الرد يكون طبيعياً، باسم مؤسسة Zaxxy دون ذكر الذكاء الاصطناعي.
    يتجنب التكرار، يذكّر المستخدم بتفعيل 'متاح' فقط إذا لم يفعلها منذ مدة.
    يوضح مزايا التطبيق مثل الدردشة والصداقات والبحث.
    """

    user = get_user_data(user_id)
    if not user:
        return "لا توجد بيانات لهذا المستخدم."

    # استخراج المعلومات المهمة
    name = user.get("name", "غير معروف")
    phone = user.get("phone", "غير معروف")
    email = user.get("email", "غير معروف")
    wilaya = user.get("wilaya", "غير معروف")
    service_type = user.get("service_type", "غير محدد")
    description = user.get("description", "لا يوجد وصف")
    is_available = user.get("is_available", 0)
    last_active = user.get("last_active")  # تاريخ آخر تفاعل للمستخدم

    # تذكير بتفعيل "متاح" فقط إذا مرت فترة طويلة
    import datetime
    reminder_message = ""
    if is_available == 0 and last_active:
        days_inactive = (datetime.datetime.now() - last_active).days
        if days_inactive >= 5:
            reminder_message = (
                "\nنذكّرك بلطف بتفعيل خاصية 'متاح' في ملفك الشخصي عندما تكون جاهزًا للعمل."
                "\nبهذه الطريقة تظهر في نتائج البحث ويستطيع الزبائن التواصل معك بسهولة."
            )

    # بناء سياق المستخدم
    user_info = (
        f"معلومات المستخدم:\n"
        f"الاسم: {name}\n"
        f"رقم الهاتف: {phone}\n"
        f"البريد الإلكتروني: {email}\n"
        f"الولاية: {wilaya}\n"
        f"نوع الخدمة: {service_type}\n"
        f"الوصف: {description}\n"
        f"الحالة: {'متاح' if is_available else 'غير متاح'}"
    )

    # سجل المحادثة السابق
    conv_rows = get_full_conversation(user_id)
    conv_text = "\n".join(f"{msg['sender']}: {msg['text']}" for msg in conv_rows) if conv_rows else "لا توجد محادثات سابقة"

    # صياغة الطلب النهائي للنموذج
    final_prompt = (
        "أنت تمثل فريق خدمة العملاء لتطبيق خدماتي، التابع لمؤسسة Zaxxy.\n"
        "مهمتك هي الرد على المستخدمين بطريقة طبيعية وبسيطة، بدون ذكر أنك روبوت أو نموذج ذكاء اصطناعي.\n"
        "اشرح للمستخدم ببساطة أي استفسار يطرحه، ووجهه بلطف إذا احتاج للمساعدة في استخدام خصائص التطبيق.\n"
        "لا تبدأ الرسالة بجمل ترحيبية متكررة، تحدث بشكل بشري طبيعي.\n"
        "اشرح بإيجاز أن التطبيق يتيح للعمال تعديل ملفهم الشخصي، تفعيل أو إطفاء 'متاح'، تغيير المهنة أو الولاية.\n"
        "وضح أن البحث يعتمد فقط على العمال المتاحين، ويمكن تعديل الحالة في أي وقت.\n"
        "اذكر أن هناك دردشة، طلبات صداقة، ووسائل لتكوين علاقات مهنية مع عمال في نفس التخصص أو تخصصات أخرى.\n"
        "اذكر الفوائد المهنية للتطبيق إذا كان السياق مناسبًا.\n"
        f"{reminder_message}\n\n"
        f"{user_info}\n\n"
        f"المحادثات الأخيرة:\n{conv_text}\n\n"
        f"سؤال المستخدم:\n{user_prompt}"
    )

    # تجهيز الطلب للنموذج
    payload = {
        "model": "deepseek/deepseek-chat:free",
        "messages": [{"role": "user", "content": final_prompt}],
    }

    # إرسال الطلب باستخدام مفتاح API عشوائي
    for key in random.sample(API_KEYS, len(API_KEYS)):
        try:
            res = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json=payload,
                timeout=10,
            )
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"OpenRouter API error with key {key}: {e}")
            continue

    return "عذرًا، حدث خطأ أثناء التواصل مع خدمة الدعم."