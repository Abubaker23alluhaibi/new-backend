const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config({ path: 'env.production' });

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// اختبار الاتصال بقاعدة البيانات
async function connectDB() {
  try {
    const MONGO_URI = process.env.MONGO_URI;
    console.log('🔍 محاولة الاتصال بقاعدة البيانات...');
    
    await mongoose.connect(MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('✅ تم الاتصال بقاعدة البيانات بنجاح');
    return true;
  } catch (error) {
    console.error('❌ فشل الاتصال بقاعدة البيانات:', error.message);
    return false;
  }
}

// تعريف النماذج
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  first_name: String,
  phone: String,
  user_type: { type: String, default: 'user' },
  createdAt: { type: Date, default: Date.now }
});

const doctorSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
  phone: String,
  specialty: String,
  province: String,
  area: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  user_type: { type: String, default: 'doctor' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Doctor = mongoose.model('Doctor', doctorSchema);

// دالة توحيد رقم الهاتف
function normalizePhone(phone) {
  let p = phone.replace(/\s+/g, '').replace(/[^+\d]/g, '');
  if (p.startsWith('0')) {
    p = '+964' + p.slice(1);
  } else if (p.startsWith('00964')) {
    p = '+964' + p.slice(5);
  } else if (p.startsWith('964')) {
    p = '+964' + p.slice(3);
  } else if (!p.startsWith('+964') && p.length === 10) {
    p = '+964' + p;
  }
  return p;
}

// API endpoints
app.post('/test-register', async (req, res) => {
  try {
    console.log('📝 طلب تسجيل جديد:', req.body);
    
    const { email, password, first_name, phone } = req.body;
    
    if (!email || !password || !first_name || !phone) {
      return res.status(400).json({ 
        error: 'جميع الحقول مطلوبة',
        received: { email, password: password ? '***' : null, first_name, phone }
      });
    }
    
    // توحيد رقم الهاتف
    const normPhone = normalizePhone(phone);
    console.log('📱 رقم الهاتف الموحد:', normPhone);
    
    // تحقق من وجود الإيميل
    const existingUser = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const existingDoctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    
    if (existingUser || existingDoctor) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقًا' });
    }
    
    // تحقق من وجود رقم الهاتف
    const phoneUser = await User.findOne({ phone: normPhone });
    const phoneDoctor = await Doctor.findOne({ phone: normPhone });
    
    if (phoneUser || phoneDoctor) {
      return res.status(400).json({ error: 'رقم الهاتف مستخدم مسبقًا' });
    }
    
    // تشفير كلمة المرور
    const hashed = await bcrypt.hash(password, 10);
    console.log('🔒 تم تشفير كلمة المرور');
    
    // إنشاء المستخدم
    const user = new User({ 
      email, 
      password: hashed, 
      first_name, 
      phone: normPhone 
    });
    
    await user.save();
    console.log('✅ تم حفظ المستخدم بنجاح');
    
    res.json({ 
      message: 'تم إنشاء الحساب بنجاح!',
      userId: user._id,
      email: user.email,
      first_name: user.first_name
    });
    
  } catch (err) {
    console.error('❌ خطأ في التسجيل:', err);
    res.status(500).json({ 
      error: 'حدث خطأ أثناء إنشاء الحساب',
      details: err.message,
      stack: err.stack
    });
  }
});

app.get('/test-appointments/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    console.log('🔍 طلب جلب مواعيد للطبيب:', doctorId);
    
    if (!doctorId || doctorId === '1') {
      return res.json([]);
    }
    
    // هنا يمكنك إضافة منطق جلب المواعيد
    res.json([]);
    
  } catch (err) {
    console.error('❌ خطأ في جلب المواعيد:', err);
    res.status(500).json({ 
      error: 'حدث خطأ أثناء جلب المواعيد',
      details: err.message
    });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// تشغيل الخادم
async function startServer() {
  const dbConnected = await connectDB();
  
  if (!dbConnected) {
    console.error('❌ فشل في الاتصال بقاعدة البيانات. إيقاف الخادم.');
    process.exit(1);
  }
  
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/health`);
    console.log(`📝 Test register: http://localhost:${PORT}/test-register`);
    console.log(`📅 Test appointments: http://localhost:${PORT}/test-appointments/123`);
  });
}

startServer();






