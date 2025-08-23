const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, 'env.production') });

// نموذج الإعلان
const advertisementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['update', 'promotion', 'announcement', 'doctor', 'center'], 
    default: 'announcement' 
  },
  status: { 
    type: String, 
    enum: ['active', 'inactive', 'pending'], 
    default: 'active' 
  },
  priority: { type: Number, default: 0 },
  target: { 
    type: String, 
    enum: ['users', 'doctors', 'both'], 
    default: 'both' 
  },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  isFeatured: { type: Boolean, default: false },
  clicks: { type: Number, default: 0 },
  views: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Advertisement = mongoose.model('Advertisement', advertisementSchema);

async function addTestAdvertisement() {
  try {
    console.log('🔗 محاولة الاتصال بقاعدة البيانات...');
    console.log('📊 رابط قاعدة البيانات:', process.env.MONGO_URI);
    
    // الاتصال بقاعدة البيانات
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ تم الاتصال بقاعدة البيانات');

    // إنشاء إعلان تجريبي للمستخدمين
    const testAdUsers = new Advertisement({
      title: 'مرحباً بك في منصة طبيبك',
      description: 'منصة طبية ذكية للعراق - احجز موعدك مع أفضل الأطباء',
      image: 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=800&h=400&fit=crop',
      type: 'announcement',
      status: 'active',
      priority: 1,
      target: 'users',
      startDate: new Date('2024-01-01'),
      endDate: new Date('2025-12-31'),
      isFeatured: true
    });

    // إنشاء إعلان تجريبي للأطباء
    const testAdDoctors = new Advertisement({
      title: 'مرحباً بك في لوحة تحكم الطبيب',
      description: 'إدارة المواعيد والمرضى بسهولة - منصة طبيبك',
      image: 'https://images.unsplash.com/photo-1576091160399-112ba8d25d1f?w=800&h=400&fit=crop',
      type: 'announcement',
      status: 'active',
      priority: 1,
      target: 'doctors',
      startDate: new Date('2024-01-01'),
      endDate: new Date('2025-12-31'),
      isFeatured: true
    });

    // إنشاء إعلان للجميع
    const testAdBoth = new Advertisement({
      title: 'تحديث جديد في المنصة',
      description: 'ميزات جديدة وتحسينات في الأداء - منصة طبيبك',
      image: 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=800&h=400&fit=crop',
      type: 'update',
      status: 'active',
      priority: 2,
      target: 'both',
      startDate: new Date('2024-01-01'),
      endDate: new Date('2025-12-31'),
      isFeatured: false
    });

    await testAdUsers.save();
    await testAdDoctors.save();
    await testAdBoth.save();
    
    console.log('✅ تم إضافة الإعلانات التجريبية بنجاح');
    console.log('📋 تفاصيل الإعلانات:', {
      users: { id: testAdUsers._id, title: testAdUsers.title, target: testAdUsers.target },
      doctors: { id: testAdDoctors._id, title: testAdDoctors.title, target: testAdDoctors.target },
      both: { id: testAdBoth._id, title: testAdBoth.title, target: testAdBoth.target }
    });

    // التحقق من وجود الإعلانات
    const allAds = await Advertisement.find({});
    console.log('📊 إجمالي الإعلانات في قاعدة البيانات:', allAds.length);
    
    const activeAds = await Advertisement.find({ status: 'active' });
    console.log('✅ الإعلانات النشطة:', activeAds.length);

    const doctorAds = await Advertisement.find({ 
      status: 'active', 
      target: { $in: ['doctors', 'both'] } 
    });
    console.log('👨‍⚕️ الإعلانات للأطباء:', doctorAds.length);

    const userAds = await Advertisement.find({ 
      status: 'active', 
      target: { $in: ['users', 'both'] } 
    });
    console.log('👤 الإعلانات للمستخدمين:', userAds.length);

    // إغلاق الاتصال
    await mongoose.connection.close();
    console.log('🔌 تم إغلاق الاتصال بقاعدة البيانات');

  } catch (error) {
    console.error('❌ خطأ:', error);
    process.exit(1);
  }
}

// تشغيل الدالة
addTestAdvertisement();
