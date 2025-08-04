# دليل حل مشاكل رفع الصور - TabibiQ

## 🚨 المشاكل الشائعة وحلولها

### 1. الصور تختفي بعد التحديث

**المشكلة:** الصور تظهر عند رفعها لأول مرة، لكنها تختفي بعد تحديث الموقع أو إعادة النشر.

**السبب:** Railway يحذف جميع الملفات المحلية عند كل إعادة نشر.

**الحل:**
- ✅ تم إعداد Cloudinary للتخزين الدائم
- ✅ الصور الجديدة تُحفظ في Cloudinary تلقائياً
- ✅ روابط دائمة للصور

### 2. فشل في رفع الصور

**المشكلة:** لا يمكن رفع الصور أو تظهر رسالة خطأ.

**الحلول:**
1. تحقق من حجم الصورة (يجب أن تكون أقل من 5MB)
2. تحقق من نوع الملف (يجب أن يكون صورة)
3. تحقق من اتصال الإنترنت
4. تحقق من إعدادات Cloudinary

### 3. الصور لا تظهر في المتصفح

**المشكلة:** الصور مُرفوعة بنجاح لكن لا تظهر في المتصفح.

**الحلول:**
1. تحقق من إعدادات CORS
2. تحقق من روابط الصور
3. امسح كاش المتصفح
4. تحقق من console errors

## 🔧 خطوات التشخيص

### 1. اختبار Cloudinary
```bash
curl https://web-production-78766.up.railway.app/test-cloudinary
```

### 2. فحص سجلات الخادم
في Railway Dashboard:
1. اذهب إلى مشروع Backend
2. اضغط على "Deployments"
3. اختر آخر deployment
4. اضغط على "View Logs"

### 3. فحص متغيرات البيئة
تأكد من وجود هذه المتغيرات في Railway:
```
CLOUDINARY_URL=cloudinary://599629738223467:Ow4bBIt20vRFBBUk1IbKLguQC98@dfbfb5r7q
CLOUDINARY_CLOUD_NAME=dfbfb5r7q
CLOUDINARY_API_KEY=599629738223467
CLOUDINARY_API_SECRET=Ow4bBIt20vRFBBUk1IbKLguQC98
```

## 📊 رسائل السجلات المهمة

### رسائل النجاح:
- `✅ Cloudinary configured successfully`
- `✅ Image uploaded to Cloudinary successfully`
- `🗑️ Local file deleted after Cloudinary upload`

### رسائل التحذير:
- `⚠️ Cloudinary URL not found, using local storage`
- `📁 Using local storage as fallback`

### رسائل الخطأ:
- `❌ Cloudinary configuration error`
- `❌ Cloudinary upload failed`
- `❌ Error in image upload`

## 🚀 الحلول السريعة

### إذا لم تعمل Cloudinary:
1. تحقق من بيانات الاعتماد
2. تأكد من وجود رصيد في Cloudinary
3. تحقق من إعدادات الحساب

### إذا لم تعمل الصور المحلية:
1. تحقق من صلاحيات المجلد
2. تأكد من وجود مساحة كافية
3. تحقق من إعدادات CORS

### إذا لم تظهر الصور في Frontend:
1. تحقق من console errors
2. امسح كاش المتصفح
3. تحقق من روابط الصور

## 📞 الدعم

إذا لم تحل المشكلة:
1. التقط screenshot للخطأ
2. انسخ رسائل السجلات
3. وصف الخطوات التي أدت للمشكلة
4. أرسل المعلومات للفريق التقني

## 🔄 التحديثات المستقبلية

- تحسين معالجة الأخطاء
- إضافة دعم لصيغ صور إضافية
- تحسين ضغط الصور
- إضافة watermark للصور 