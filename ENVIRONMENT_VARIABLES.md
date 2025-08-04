# متغيرات البيئة المطلوبة للمشروع

## 🖥️ متغيرات الباك إند (Railway)

### إضافة هذه المتغيرات في لوحة تحكم Railway:

```bash
# إعدادات الخادم
NODE_ENV=production
PORT=10000

# قاعدة البيانات
MONGO_URI=mongodb+srv://1223BAKErKreem:Akincilar12AltajiBaGHDad22@cluster0.d2mdyuw.mongodb.net/tabibiq?retryWrites=true&w=majority

# JWT (مطلوب للمصادقة)
JWT_SECRET=tabibiq_jwt_secret_2024_secure_key_xyz789_production_environment

# CORS (للسماح بالوصول من الفرونت إند)
CORS_ORIGIN=https://tabib-iq.netlify.app

# عنوان الباك إند
API_URL=https://web-production-78766.up.railway.app

# Cloudinary (لتخزين الصور بشكل دائم)
CLOUDINARY_URL=cloudinary://599629738223467:Ow4bBIt20vRFBBUk1IbKLguQC98@dfbfb5r7q

# إعدادات رفع الملفات
MAX_FILE_SIZE=5242880
UPLOAD_PATH=./uploads
```

## 🎨 متغيرات الفرونت إند (Vercel/Netlify)

### إضافة هذه المتغيرات في لوحة تحكم Vercel أو Netlify:

```bash
# عنوان الباك إند
REACT_APP_API_URL=https://web-production-78766.up.railway.app

# إعدادات البيئة
REACT_APP_ENV=production
NODE_ENV=production

# إعدادات البناء
GENERATE_SOURCEMAP=false
```

## 📝 ملاحظات مهمة:

1. **JWT_SECRET**: مطلوب للمصادقة - لا تشاركه مع أحد
2. **CLOUDINARY_URL**: لحل مشكلة اختفاء الصور
3. **CORS_ORIGIN**: يجب أن يتطابق مع عنوان الفرونت إند
4. **API_URL**: عنوان الباك إند في Railway
5. **REACT_APP_API_URL**: نفس عنوان الباك إند للفرونت إند

## 🔧 كيفية الإضافة:

### Railway:
1. اذهب إلى لوحة تحكم Railway
2. اختر مشروع الباك إند
3. اذهب إلى Variables
4. أضف كل متغير على حدة

### Vercel:
1. اذهب إلى لوحة تحكم Vercel
2. اختر مشروع الفرونت إند
3. اذهب إلى Settings > Environment Variables
4. أضف المتغيرات

### Netlify:
1. اذهب إلى لوحة تحكم Netlify
2. اختر مشروع الفرونت إند
3. اذهب إلى Site settings > Environment variables
4. أضف المتغيرات 