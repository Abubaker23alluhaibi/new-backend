const mongoose = require('mongoose');
require('dotenv').config({ path: './env.production' });

// مخطط الإعلانات المتحركة
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

async function addDoctorAdvertisements() {
  try {
    console.log('🔗 محاولة الاتصال بقاعدة البيانات...');
    
    // الاتصال بقاعدة البيانات
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ تم الاتصال بقاعدة البيانات');

    // إنشاء إعلانات تجريبية للأطباء
    const doctorAds = [
      {
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
      },
      {
        title: 'ميزات جديدة في لوحة التحكم',
        description: 'إحصائيات متقدمة وتقارير مفصلة لتحسين الخدمة',
        image: 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=800&h=400&fit=crop',
        type: 'update',
        status: 'active',
        priority: 2,
        target: 'doctors',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2025-12-31'),
        isFeatured: false
      },
      {
        title: 'نصائح لتحسين الخدمة الطبية',
        description: 'أفضل الممارسات لزيادة رضا المرضى',
        image: 'https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=800&h=400&fit=crop',
        type: 'promotion',
        status: 'active',
        priority: 3,
        target: 'doctors',
        startDate: new Date('2024-01-01'),
        endDate: new Date('2025-12-31'),
        isFeatured: false
      }
    ];

    // إضافة الإعلانات
    for (const adData of doctorAds) {
      const ad = new Advertisement(adData);
      await ad.save();
      console.log('✅ تم إضافة إعلان:', ad.title);
    }

    // التحقق من وجود الإعلانات
    const allAds = await Advertisement.find({});
    console.log('📊 إجمالي الإعلانات في قاعدة البيانات:', allAds.length);
    
    const doctorAdsCount = await Advertisement.find({ 
      status: 'active', 
      target: { $in: ['doctors', 'both'] } 
    });
    console.log('👨‍⚕️ الإعلانات للأطباء:', doctorAdsCount.length);

    const userAdsCount = await Advertisement.find({ 
      status: 'active', 
      target: { $in: ['users', 'both'] } 
    });
    console.log('👤 الإعلانات للمستخدمين:', userAdsCount.length);

    // إغلاق الاتصال
    await mongoose.connection.close();
    console.log('🔌 تم إغلاق الاتصال بقاعدة البيانات');
    console.log('🎉 تم إضافة إعلانات الأطباء بنجاح!');

  } catch (error) {
    console.error('❌ خطأ:', error);
    process.exit(1);
  }
}

// تشغيل الدالة
addDoctorAdvertisements();


