# إعداد Cloudinary - مثال آمن

## المشكلة
عند إعادة نشر التطبيق على Railway، يتم حذف جميع الصور المرفوعة لأن Railway يستخدم نظام ملفات مؤقت.

## الحل: استخدام Cloudinary

### الخطوة 1: إنشاء حساب Cloudinary
1. اذهب إلى [cloudinary.com](https://cloudinary.com)
2. أنشئ حساب مجاني
3. احصل على بيانات الاعتماد:
   - Cloud Name
   - API Key
   - API Secret

### الخطوة 2: إعداد متغيرات البيئة في Railway
في لوحة تحكم Railway، أضف المتغيرات التالية:

```
CLOUDINARY_URL=cloudinary://your_api_key:your_api_secret@your_cloud_name
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret
```

### الخطوة 3: اختبار الإعداد
بعد إضافة المتغيرات، يمكنك اختبار Cloudinary عبر:
```
GET https://your-backend-domain.railway.app/test-cloudinary
```

## ملاحظات مهمة
- Cloudinary يوفر 25GB مجاناً شهرياً
- الصور تُحفظ في مجلد `tabibiq-profiles`
- يتم تحسين الصور تلقائياً (400x400 بكسل)
- إذا فشل Cloudinary، سيتم استخدام التخزين المحلي كبديل
- الملفات المحلية تُحذف تلقائياً بعد يوم واحد

## ⚠️ تحذير أمني
- لا تضع API keys حقيقية في هذا الملف
- استخدم متغيرات البيئة في Railway فقط
- احتفظ بالمفاتيح الحقيقية سراً
