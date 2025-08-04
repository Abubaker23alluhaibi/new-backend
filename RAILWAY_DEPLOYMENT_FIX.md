# حل مشكلة npm ci في Railway

## المشكلة
```
npm error `npm ci` can only install packages when your package.json and package-lock.json or npm-shrinkwrap.json are in sync.
npm error Missing: cloudinary@1.41.3 from lock file
```

## الحل

### الخطوة 1: تحديث package-lock.json محلياً
```bash
cd backend-iq
npm install
```

### الخطوة 2: رفع التحديثات إلى GitHub
```bash
git add .
git commit -m "Update package-lock.json with cloudinary dependency"
git push
```

### الخطوة 3: إعادة النشر على Railway
- سيتم إعادة النشر تلقائياً بعد رفع التحديثات
- أو يمكنك إعادة النشر يدوياً من لوحة تحكم Railway

## متغيرات البيئة المطلوبة في Railway

تأكد من إضافة هذه المتغيرات في Railway:

```bash
NODE_ENV=production
PORT=10000
MONGO_URI=mongodb+srv://1223BAKErKreem:Akincilar12AltajiBaGHDad22@cluster0.d2mdyuw.mongodb.net/tabibiq?retryWrites=true&w=majority
JWT_SECRET=tabibiq_jwt_secret_2024_secure_key_xyz789_production_environment
CORS_ORIGIN=https://tabib-iq.netlify.app
API_URL=https://web-production-78766.up.railway.app
CLOUDINARY_URL=cloudinary://599629738223467:Ow4bBIt20vRFBBUk1IbKLguQC98@dfbfb5r7q
MAX_FILE_SIZE=5242880
UPLOAD_PATH=./uploads
```

## ملاحظات مهمة

1. **package-lock.json**: يجب أن يكون محدثاً مع package.json
2. **Cloudinary**: تم إضافته لحل مشكلة اختفاء الصور
3. **المتغيرات**: تأكد من إضافة جميع المتغيرات المطلوبة
4. **إعادة النشر**: قد يستغرق بضع دقائق

## اختبار الحل

بعد إعادة النشر:
1. تحقق من سجلات Railway للتأكد من عدم وجود أخطاء
2. اختبر رفع صورة جديدة
3. تأكد من عدم اختفاء الصور بعد التحديثات 