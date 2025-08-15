const mongoose = require('mongoose');
require('dotenv').config({ path: 'env.production' });

// اختبار جميع API endpoints
async function testAllAPIs() {
  try {
    console.log('🚀 بدء اختبار جميع API endpoints...\n');
    
    // 1. اختبار الاتصال بقاعدة البيانات
    console.log('1️⃣ اختبار قاعدة البيانات...');
    const MONGO_URI = process.env.MONGO_URI;
    
    if (!MONGO_URI) {
      throw new Error('متغير MONGO_URI غير موجود');
    }
    
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ قاعدة البيانات تعمل\n');
    
    // 2. اختبار النماذج
    console.log('2️⃣ اختبار النماذج...');
    
    const User = mongoose.model('User', new mongoose.Schema({
      email: { type: String, unique: true },
      password: String,
      first_name: String,
      phone: String,
      user_type: { type: String, default: 'user' },
      createdAt: { type: Date, default: Date.now }
    }));
    
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
    
    const Appointment = mongoose.model('Appointment', new mongoose.Schema({
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
      userName: String,
      doctorName: String,
      date: String,
      time: String,
      status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
      createdAt: { type: Date, default: Date.now }
    }));
    
    const Notification = mongoose.model('Notification', new mongoose.Schema({
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
      type: String,
      message: String,
      read: { type: Boolean, default: false },
      createdAt: { type: Date, default: Date.now }
    }));
    
    console.log('✅ جميع النماذج تعمل\n');
    
    // 3. اختبار البيانات الموجودة
    console.log('3️⃣ اختبار البيانات الموجودة...');
    
    const users = await User.find({}).limit(3);
    const doctors = await Doctor.find({}).limit(3);
    const appointments = await Appointment.find({}).limit(3);
    const notifications = await Notification.find({}).limit(3);
    
    console.log(`📊 المستخدمين: ${users.length}`);
    console.log(`👨‍⚕️ الأطباء: ${doctors.length}`);
    console.log(`📅 المواعيد: ${appointments.length}`);
    console.log(`🔔 الإشعارات: ${notifications.length}\n`);
    
    // 4. اختبار إنشاء بيانات تجريبية
    console.log('4️⃣ اختبار إنشاء بيانات تجريبية...');
    
    // إنشاء مستخدم تجريبي
    const testUser = new User({
      email: 'test@test.com',
      password: 'hashedpassword',
      first_name: 'مستخدم تجريبي',
      phone: '+9647501234567',
      user_type: 'user'
    });
    
    await testUser.save();
    console.log('✅ تم إنشاء مستخدم تجريبي');
    
    // إنشاء طبيب تجريبي
    const testDoctor = new Doctor({
      email: 'doctor@test.com',
      password: 'hashedpassword',
      name: 'د. طبيب تجريبي',
      phone: '+9647501234568',
      specialty: 'طب عام',
      province: 'بغداد',
      area: 'الكرادة',
      status: 'approved'
    });
    
    await testDoctor.save();
    console.log('✅ تم إنشاء طبيب تجريبي');
    
    // إنشاء موعد تجريبي
    const testAppointment = new Appointment({
      userId: testUser._id,
      doctorId: testDoctor._id,
      userName: testUser.first_name,
      doctorName: testDoctor.name,
      date: '2024-12-20',
      time: '10:00',
      status: 'pending'
    });
    
    await testAppointment.save();
    console.log('✅ تم إنشاء موعد تجريبي');
    
    // إنشاء إشعار تجريبي
    const testNotification = new Notification({
      userId: testUser._id,
      doctorId: testDoctor._id,
      type: 'appointment',
      message: 'موعد جديد مع د. طبيب تجريبي',
      read: false
    });
    
    await testNotification.save();
    console.log('✅ تم إنشاء إشعار تجريبي\n');
    
    // 5. اختبار API endpoints
    console.log('5️⃣ اختبار API endpoints...');
    
    // اختبار جلب المواعيد
    const userAppointments = await Appointment.find({ userId: testUser._id });
    console.log(`📅 مواعيد المستخدم: ${userAppointments.length}`);
    
    // اختبار جلب إشعارات الطبيب
    const doctorNotifications = await Notification.find({ doctorId: testDoctor._id });
    console.log(`🔔 إشعارات الطبيب: ${doctorNotifications.length}`);
    
    // اختبار البحث عن طبيب
    const foundDoctor = await Doctor.findOne({ email: 'doctor@test.com' });
    console.log(`👨‍⚕️ الطبيب موجود: ${foundDoctor ? 'نعم' : 'لا'}`);
    
    // اختبار البحث عن مستخدم
    const foundUser = await User.findOne({ email: 'test@test.com' });
    console.log(`👤 المستخدم موجود: ${foundUser ? 'نعم' : 'لا'}\n`);
    
    // 6. تنظيف البيانات التجريبية
    console.log('6️⃣ تنظيف البيانات التجريبية...');
    
    await Appointment.deleteOne({ _id: testAppointment._id });
    await Notification.deleteOne({ _id: testNotification._id });
    await Doctor.deleteOne({ _id: testDoctor._id });
    await User.deleteOne({ _id: testUser._id });
    
    console.log('✅ تم تنظيف البيانات التجريبية\n');
    
    // 7. إغلاق الاتصال
    await mongoose.connection.close();
    console.log('🎉 جميع الاختبارات نجحت! الخادم يجب أن يعمل بشكل صحيح.');
    
  } catch (error) {
    console.error('❌ فشل في الاختبار:', error.message);
    
    if (error.name === 'MongooseServerSelectionError') {
      console.error('💡 المشكلة: فشل الاتصال بقاعدة البيانات');
    } else if (error.name === 'ValidationError') {
      console.error('💡 المشكلة: خطأ في التحقق من البيانات');
    } else if (error.code === 11000) {
      console.error('💡 المشكلة: تكرار في البيانات الفريدة');
    }
    
    console.error('🔍 تفاصيل الخطأ:', error);
    process.exit(1);
  }
}

// تشغيل الاختبار
testAllAPIs();




