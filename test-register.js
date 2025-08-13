const mongoose = require('mongoose');
require('dotenv').config({ path: 'env.production' });

// اختبار الاتصال بقاعدة البيانات
async function testDatabaseConnection() {
  try {
    const MONGO_URI = process.env.MONGO_URI;
    
    if (!MONGO_URI) {
      console.error('❌ متغير MONGO_URI غير موجود في ملف البيئة');
      process.exit(1);
    }
    
    console.log('🔍 محاولة الاتصال بقاعدة البيانات...');
    console.log('📊 URI:', MONGO_URI.replace(/\/\/.*@/, '//***:***@')); // إخفاء كلمة المرور
    
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
    console.log('📊 قاعدة البيانات:', mongoose.connection.name);
    console.log('🌐 المضيف:', mongoose.connection.host);
    console.log('🔌 المنفذ:', mongoose.connection.port);
    
    // اختبار إنشاء مستخدم
    const User = mongoose.model('User', new mongoose.Schema({
      email: { type: String, unique: true },
      password: String,
      first_name: String,
      phone: String,
      user_type: { type: String, default: 'user' },
      createdAt: { type: Date, default: Date.now }
    }));
    
    // اختبار إنشاء طبيب
    const Doctor = mongoose.model('Doctor', new mongoose.Schema({
      email: { type: String, unique: true },
      password: String,
      name: String,
      phone: String,
      specialty: String,
      province: String,
      area: String,
      user_type: { type: String, default: 'doctor' },
      status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
      createdAt: { type: Date, default: Date.now }
    }));
    
    console.log('✅ تم إنشاء النماذج بنجاح');
    
    // اختبار البحث عن مستخدمين موجودين
    const users = await User.find({}).limit(5);
    const doctors = await Doctor.find({}).limit(5);
    
    console.log(`📊 المستخدمين: ${users.length}`);
    console.log(`👨‍⚕️ الأطباء: ${doctors.length}`);
    
    await mongoose.connection.close();
    console.log('✅ تم إغلاق الاتصال بنجاح');
    
  } catch (error) {
    console.error('❌ خطأ في اختبار قاعدة البيانات:', error.message);
    
    if (error.name === 'MongooseServerSelectionError') {
      console.error('💡 المشكلة: فشل الاتصال بقاعدة البيانات');
      console.error('💡 الحل: تأكد من أن الخادم يعمل وأن متغيرات البيئة صحيحة');
    }
    
    process.exit(1);
  }
}

// تشغيل الاختبار
testDatabaseConnection();
