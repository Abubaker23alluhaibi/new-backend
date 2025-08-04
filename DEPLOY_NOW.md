# نشر سريع - TabibiQ Backend

## 🚀 خطوات النشر السريع

### 1. رفع التحديثات إلى GitHub
```bash
cd backend-iq
git add .
git commit -m "Fix image upload issues - add Cloudinary integration and test endpoints"
git push origin main
```

### 2. انتظار النشر التلقائي
- Railway سينشر التحديثات تلقائياً
- انتظر 2-3 دقائق حتى يكتمل النشر

### 3. اختبار النظام
بعد النشر، اختبر هذه الروابط:

#### اختبار حالة الخادم:
```
https://web-production-78766.up.railway.app/server-status
```

#### اختبار Cloudinary:
```
https://web-production-78766.up.railway.app/test-cloudinary
```

#### اختبار نظام رفع الصور:
```
https://web-production-78766.up.railway.app/test-image-upload
```

## 🔧 إذا لم يعمل النشر

### 1. تحقق من Railway Dashboard
1. اذهب إلى [railway.app](https://railway.app)
2. اختر مشروع Backend
3. تحقق من "Deployments"
4. ابحث عن أخطاء في السجلات

### 2. تحقق من متغيرات البيئة
تأكد من وجود هذه المتغيرات في Railway:
```
CLOUDINARY_URL=cloudinary://599629738223467:Ow4bBIt20vRFBBUk1IbKLguQC98@dfbfb5r7q
CLOUDINARY_CLOUD_NAME=dfbfb5r7q
CLOUDINARY_API_KEY=599629738223467
CLOUDINARY_API_SECRET=Ow4bBIt20vRFBBUk1IbKLguQC98
```

### 3. إعادة النشر يدوياً
في Railway Dashboard:
1. اضغط على "Deployments"
2. اضغط على "Deploy Now"

## ✅ النتيجة المتوقعة

بعد النشر الناجح:
- ✅ جميع endpoints تعمل
- ✅ Cloudinary مُعد بشكل صحيح
- ✅ نظام رفع الصور جاهز
- ✅ الصور لن تختفي بعد التحديث

## 📞 إذا استمرت المشاكل

1. تحقق من سجلات Railway
2. تأكد من متغيرات البيئة
3. أعد نشر التطبيق
4. اتصل بالفريق التقني 