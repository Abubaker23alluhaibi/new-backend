# دليل الاختبار السريع - TabibiQ Backend

## 🚀 اختبار النظام

### 1. اختبار حالة الخادم
```bash
curl https://web-production-78766.up.railway.app/server-status
```

### 2. اختبار الصحة العامة
```bash
curl https://web-production-78766.up.railway.app/api/health
```

### 3. اختبار Cloudinary
```bash
curl https://web-production-78766.up.railway.app/test-cloudinary
```

### 4. اختبار نظام رفع الصور
```bash
curl https://web-production-78766.up.railway.app/test-image-upload
```

## 📊 النتائج المتوقعة

### server-status
```json
{
  "status": "running",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "environment": "production",
  "cloudinary": {
    "configured": true,
    "cloudName": "dfbfb5r7q",
    "apiKey": "Set"
  },
  "upload": {
    "directory": "/app/uploads",
    "exists": true
  }
}
```

### test-cloudinary
```json
{
  "status": "success",
  "message": "Cloudinary يعمل بشكل صحيح",
  "cloudinaryConfigured": true,
  "ping": { "status": "ok" }
}
```

## 🔧 إذا لم تعمل endpoints

### 1. تحقق من النشر
- تأكد من أن التحديثات تم رفعها إلى GitHub
- تحقق من Railway Dashboard للتأكد من النشر

### 2. تحقق من السجلات
في Railway Dashboard:
1. اذهب إلى مشروع Backend
2. اضغط على "Deployments"
3. اختر آخر deployment
4. اضغط على "View Logs"

### 3. تحقق من متغيرات البيئة
تأكد من وجود هذه المتغيرات في Railway:
```
CLOUDINARY_URL=cloudinary://599629738223467:Ow4bBIt20vRFBBUk1IbKLguQC98@dfbfb5r7q
CLOUDINARY_CLOUD_NAME=dfbfb5r7q
CLOUDINARY_API_KEY=599629738223467
CLOUDINARY_API_SECRET=Ow4bBIt20vRFBBUk1IbKLguQC98
```

## 🎯 اختبار رفع الصور

### 1. اختبار رفع صورة
```bash
curl -X POST \
  -F "image=@/path/to/your/image.jpg" \
  https://web-production-78766.up.railway.app/upload-profile-image
```

### 2. النتيجة المتوقعة
```json
{
  "success": true,
  "imageUrl": "https://res.cloudinary.com/dfbfb5r7q/image/upload/v1234567890/tabibiq-profiles/profile-1234567890.jpg",
  "uploadSuccess": true,
  "message": "تم رفع الصورة بنجاح"
}
```

## 📞 إذا استمرت المشاكل

1. تحقق من سجلات Railway
2. تأكد من متغيرات البيئة
3. أعد نشر التطبيق
4. اتصل بالفريق التقني 