const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, 'env.local') });

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

    // إنشاء إعلان تجريبي
    const testAd = new Advertisement({
      title: 'مرحباً بك في منصة طبيبك',
      description: 'منصة طبية ذكية للعراق - احجز موعدك مع أفضل الأطباء',
      image: 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=800&h=400&fit=crop',
      type: 'announcement',
      status: 'active',
      priority: 1,
      target: 'both',
      startDate: new Date('2024-01-01'),
      endDate: new Date('2025-12-31'),
      isFeatured: true
    });

    await testAd.save();
    console.log('✅ تم إضافة الإعلان التجريبي بنجاح');
    console.log('📋 تفاصيل الإعلان:', {
      id: testAd._id,
      title: testAd.title,
      status: testAd.status,
      target: testAd.target
    });

    // التحقق من وجود الإعلانات
    const allAds = await Advertisement.find({});
    console.log('📊 إجمالي الإعلانات في قاعدة البيانات:', allAds.length);
    
    const activeAds = await Advertisement.find({ status: 'active' });
    console.log('✅ الإعلانات النشطة:', activeAds.length);

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
