# utils/ai_search.py
import requests
import random
import sqlite3




API_KEYS = [
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    "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",
    # ... up to 20
]
# جلب بيانات المستخدم


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