require('dotenv').config({ path: process.env.NODE_ENV === 'production' ? '.env' : 'env.local' });
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cloudinary = require('cloudinary').v2;

const app = express();
// إعدادات CORS محسنة للوصول من الهاتف
const allowedOrigins = [
  'https://www.tabib-iq.com',
  'https://tabib-iq.com',
  'https://tabib-iq-frontend.vercel.app',
  'https://new-frontend-livid-beta.vercel.app',
  'https://new-frontend-hetxz9vv9-abubakers-projects-f1e3718d.vercel.app',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    // السماح للطلبات بدون origin (مثل mobile apps)
    if (!origin) return callback(null, true);
    
    // السماح لأي رابط من Vercel
    if (origin.includes('vercel.app') || origin.includes('netlify.app')) {
      return callback(null, true);
    }
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('🚫 Blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// إعداد مجلد رفع الصور
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// دالة لتنظيف الملفات المحلية القديمة
const cleanupOldFiles = () => {
  try {
    if (fs.existsSync(uploadDir)) {
      const files = fs.readdirSync(uploadDir);
      const now = Date.now();
      const oneDay = 24 * 60 * 60 * 1000; // يوم واحد بالميلي ثانية
      
      files.forEach(file => {
        const filePath = path.join(uploadDir, file);
        const stats = fs.statSync(filePath);
        
        // حذف الملفات الأقدم من يوم واحد
        if (now - stats.mtime.getTime() > oneDay) {
          fs.unlinkSync(filePath);
          console.log(`🗑️ Deleted old file: ${file}`);
        }
      });
    }
  } catch (error) {
    console.error('❌ Error cleaning up old files:', error);
  }
};

// تنظيف الملفات كل ساعة
setInterval(cleanupOldFiles, 60 * 60 * 1000);

// تنظيف الملفات عند بدء التطبيق
cleanupOldFiles();

// إعداد Cloudinary
if (process.env.CLOUDINARY_URL) {
  try {
    cloudinary.config({
      cloud_name: process.env.CLOUDINARY_CLOUD_NAME || 'dfbfb5r7q',
      api_key: process.env.CLOUDINARY_API_KEY || '599629738223467',
      api_secret: process.env.CLOUDINARY_API_SECRET || 'Ow4bBIt20vRFBBUk1IbKLguQC98'
    });
    console.log('✅ Cloudinary configured successfully');
  } catch (error) {
    console.error('❌ Cloudinary configuration error:', error);
  }
} else {
  console.log('⚠️ Cloudinary URL not found, using local storage');
}

// إعداد multer لرفع الصور
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // التأكد من وجود المجلد
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // إنشاء اسم فريد للملف
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = path.extname(file.originalname);
    cb(null, `profile-${uniqueSuffix}${extension}`);
  }
});

const fileFilter = (req, file, cb) => {
  // التحقق من نوع الملف
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('يجب أن يكون الملف صورة'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  }
});

// اتصال MongoDB
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/tabibiq';

// دالة إعادة الاتصال بقاعدة البيانات
const connectToMongoDB = async (retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`🔄 Attempting to connect to MongoDB (attempt ${i + 1}/${retries})...`);
      await mongoose.connect(MONGO_URI, connectionOptions);
      console.log('✅ Connected to MongoDB successfully');
      console.log('📊 Database:', mongoose.connection.name);
      console.log('🌐 Host:', mongoose.connection.host);
      console.log('🔌 Port:', mongoose.connection.port);
      return true;
    } catch (err) {
      console.error(`❌ MongoDB connection attempt ${i + 1} failed:`, err.message);
      if (i < retries - 1) {
        console.log(`⏳ Retrying in 5 seconds...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  }
  console.error('❌ All MongoDB connection attempts failed');
  return false;
};

console.log('🔗 Attempting to connect to MongoDB...');
console.log('📝 MONGO_URI:', MONGO_URI);
console.log('🏠 Environment:', process.env.NODE_ENV || 'development');

// إعدادات الاتصال المناسبة للبيئة
const connectionOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  maxPoolSize: 10,
  retryWrites: true,
  w: 'majority'
};

// محاولة الاتصال بقاعدة البيانات
connectToMongoDB().then((connected) => {
  if (!connected) {
    console.log('⚠️  Server will continue without database connection');
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'TabibiQ Backend API',
    version: '1.0.0',
    status: 'running',
    endpoints: {
      health: '/api/health',
      docs: 'API documentation available'
    }
  });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// مخطط المستخدمين
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  first_name: String,
  phone: String,
  avatar: String,
  profileImage: String, // الصورة الشخصية للمستخدم
  active: { type: Boolean, default: true },
  disabled: { type: Boolean, default: false }, // تعطيل الحساب
  user_type: { type: String, default: 'user' }, // إضافة حقل user_type
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// مخطط الأطباء
const doctorSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
  phone: String,
  specialty: String,
  province: String,
  area: String,
  clinicLocation: String,
  mapLocation: String, // رابط الموقع على الخريطة
  image: String,
  profileImage: String, // الصورة الشخصية للطبيب
  idFront: String,
  idBack: String,
  syndicateFront: String,
  syndicateBack: String,
  about: String,
  workTimes: Array,
  experienceYears: { type: Number, default: 0 },
  centerId: { type: mongoose.Schema.Types.ObjectId, ref: 'HealthCenter' }, // ربط بالمركز
  isIndependent: { type: Boolean, default: true }, // هل يعمل بشكل مستقل
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  active: { type: Boolean, default: true },
  disabled: { type: Boolean, default: false }, // تعطيل الحساب
  is_featured: { type: Boolean, default: false },
  user_type: { type: String, default: 'doctor' }, // إضافة حقل user_type
  created_at: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  appointmentDuration: { type: Number, default: 30 }, // مدة الموعد الافتراضية بالدقائق
});
const Doctor = mongoose.model('Doctor', doctorSchema);

// مخطط الحجوزات
const appointmentSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  centerId: { type: mongoose.Schema.Types.ObjectId, ref: 'HealthCenter' }, // إضافة المركز
  serviceType: { type: String, enum: ['doctor', 'lab', 'xray', 'therapy', 'other'], default: 'doctor' }, // نوع الخدمة
  serviceName: String, // اسم الخدمة المحددة
  userName: String,
  doctorName: String,
  centerName: String,
  date: String,
  time: String,
  reason: String,
  status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
  price: Number,
  notes: String,
  type: { type: String, enum: ['normal', 'special_appointment'], default: 'normal' }, // <-- أضف هذا السطر
  patientPhone: String, // <-- أضفت هذا السطر لحفظ رقم الهاتف
  duration: { type: Number, default: 30 }, // مدة الموعد بالدقائق
  createdAt: { type: Date, default: Date.now }
});
const Appointment = mongoose.model('Appointment', appointmentSchema);

// مخطط الرسائل
const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
  text: String,
  image: String,
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// مخطط الإشعارات
const notificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  type: String,
  message: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Notification = mongoose.model('Notification', notificationSchema);

// مخطط الأطباء المميزين
const featuredDoctorSchema = new mongoose.Schema({
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
  priority: { type: Number, default: 0 }, // الأولوية في الترتيب
  createdAt: { type: Date, default: Date.now }
});
const FeaturedDoctor = mongoose.model('FeaturedDoctor', featuredDoctorSchema);

// مخطط الأدمن
const adminSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String,
  role: { type: String, default: 'admin' },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Admin = mongoose.model('Admin', adminSchema);

// مخطط المراكز الصحية
const healthCenterSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  phone: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['health_center', 'hospital', 'clinic'], 
    default: 'health_center' 
  },
  description: String,
  location: {
    province: String,
    area: String,
    fullAddress: String,
    coordinates: {
      lat: Number,
      lng: Number
    }
  },
  services: [{
    name: String,
    description: String,
    price: Number,
    available: { type: Boolean, default: true }
  }],
  specialties: [String], // التخصصات المتوفرة
  doctors: [{
    doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
    name: String,
    specialty: String,
    experience: String,
    education: String,
    workingHours: String,
    description: String,
    phone: String,
    email: String,
    addedAt: { type: Date, default: Date.now }
  }],
  branches: [{
    name: String,
    location: String,
    phone: String,
    active: { type: Boolean, default: true }
  }],
  workingHours: {
    sunday: { from: String, to: String, closed: { type: Boolean, default: false } },
    monday: { from: String, to: String, closed: { type: Boolean, default: false } },
    tuesday: { from: String, to: String, closed: { type: Boolean, default: false } },
    wednesday: { from: String, to: String, closed: { type: Boolean, default: false } },
    thursday: { from: String, to: String, closed: { type: Boolean, default: false } },
    friday: { from: String, to: String, closed: { type: Boolean, default: false } },
    saturday: { from: String, to: String, closed: { type: Boolean, default: false } }
  },
  images: {
    logo: String,
    cover: String,
    gallery: [String]
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected'], 
    default: 'pending' 
  },
  active: { type: Boolean, default: true },
  is_featured: { type: Boolean, default: false },
  rating: { type: Number, default: 0 },
  reviews: [{ 
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rating: Number,
    comment: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const HealthCenter = mongoose.model('HealthCenter', healthCenterSchema);

console.log('MongoDB schemas initialized');

// دالة توحيد رقم الهاتف العراقي
function normalizePhone(phone) {
  let p = phone.replace(/\s+/g, '').replace(/[^+\d]/g, '');
  if (p.startsWith('0')) {
    p = '+964' + p.slice(1);
  } else if (p.startsWith('00964')) {
    p = '+964' + p.slice(5);
  } else if (p.startsWith('964')) {
    p = '+964' + p.slice(3);
  } else if (!p.startsWith('+964') && p.length === 10) {
    // إذا الرقم 10 أرقام فقط (بدون صفر أو كود)، أضف +964
    p = '+964' + p;
  }
  return p;
}

// دالة إضافة "د." تلقائياً لاسم الطبيب
function formatDoctorName(name) {
  if (!name) return name;
  
  // إزالة "د." إذا كانت موجودة مسبقاً لتجنب التكرار
  let cleanName = name.replace(/^د\.\s*/, '').trim();
  
  // إضافة "د." في البداية
  return `د. ${cleanName}`;
}

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
  try {
    const { email, password, first_name, phone } = req.body;
    // توحيد رقم الهاتف
    const normPhone = normalizePhone(phone);
    // تحقق من وجود الإيميل في User أو Doctor (case-insensitive)
    const existingUser = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const existingDoctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (existingUser || existingDoctor) return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقًا' });
    // تحقق من وجود رقم الهاتف في User أو Doctor
    const phoneUser = await User.findOne({ phone: normPhone });
    const phoneDoctor = await Doctor.findOne({ phone: normPhone });
    if (phoneUser || phoneDoctor) return res.status(400).json({ error: 'رقم الهاتف مستخدم مسبقًا' });
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, first_name, phone: normPhone });
    await user.save();
    res.json({ message: 'تم إنشاء الحساب بنجاح!' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

// تسجيل طبيب جديد (مع إرسال الوثائق على الواتساب)
app.post('/register-doctor', upload.single('image'), async (req, res) => {
  try {
    const {
      email, password, name, phone, specialty, province, area, clinicLocation, mapLocation, about, workTimes
    } = req.body;
    
    // توحيد رقم الهاتف
    const normPhone = normalizePhone(phone);
    
    // تحقق من وجود الإيميل في قاعدة البيانات (case-insensitive)
    const existingDoctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const existingUser = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    
    if (existingDoctor || existingUser) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقًا' });
    }
    
    // تحقق من وجود رقم الهاتف في User أو Doctor
    const phoneUser = await User.findOne({ phone: normPhone });
    const phoneDoctor = await Doctor.findOne({ phone: normPhone });
    if (phoneUser || phoneDoctor) return res.status(400).json({ error: 'رقم الهاتف مستخدم مسبقًا' });
    
    // تشفير كلمة المرور
    const hashed = await bcrypt.hash(password, 10);
    
    // مسار الصورة الشخصية فقط (اختيارية)
    const imagePath = req.file ? `/uploads/${req.file.filename}` : '';
    
    // إنشاء الطبيب الجديد
    const doctor = new Doctor({
      email,
      password: hashed,
      name: formatDoctorName(name), // إضافة "د." تلقائياً
      phone: normPhone,
      specialty,
      province,
      area,
      clinicLocation,
      mapLocation, // رابط الموقع على الخريطة
      image: imagePath, // الصورة الشخصية فقط
      about,
      workTimes: workTimes ? JSON.parse(workTimes) : [],
      experienceYears: req.body.experienceYears || 0,
      appointmentDuration: req.body.appointmentDuration ? Number(req.body.appointmentDuration) : 30,
      user_type: 'doctor',
      status: 'pending' // في انتظار إرسال الوثائق
    });
    
    await doctor.save();
    
    // إنشاء رابط الواتساب لإرسال الوثائق
    const whatsappNumber = '+9647769012619';
    const doctorInfo = `👨‍⚕️ طبيب جديد: ${formatDoctorName(name)}\n📧 البريد: ${email}\n📱 الهاتف: ${normPhone}\n🏥 التخصص: ${specialty}\n📍 المحافظة: ${province}`;
    
    const whatsappMessage = encodeURIComponent(`مرحباً! 👋

${doctorInfo}

📋 المطلوب إرساله:
1️⃣ صورة الهوية الشخصية (الوجه)
2️⃣ صورة الهوية الشخصية (الظهر)  
3️⃣ صورة شهادة النقابة (الوجه)
4️⃣ صورة شهادة النقابة (الظهر)

📞 رقم الهاتف: ${normPhone}
📧 البريد الإلكتروني: ${email}

شكراً لك! 🙏`);

    const whatsappLink = `https://wa.me/${whatsappNumber}?text=${whatsappMessage}`;
    
    res.json({ 
      message: 'تم إنشاء حساب الطبيب بنجاح! يرجى إرسال الوثائق المطلوبة على الواتساب.',
      whatsappLink: whatsappLink,
      whatsappNumber: whatsappNumber,
      doctorInfo: doctorInfo,
      requiredDocuments: [
        'صورة الهوية الشخصية (الوجه)',
        'صورة الهوية الشخصية (الظهر)',
        'صورة شهادة النقابة (الوجه)',
        'صورة شهادة النقابة (الظهر)'
      ]
    });
    
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

// تسجيل الدخول (حسب نوع الحساب)
app.post('/login', async (req, res) => {
  try {
    let { email, password, loginType } = req.body;
    // إذا كان input لا يحتوي @ اعتبره رقم هاتف
    let isPhone = false;
    if (email && !email.includes('@')) {
      isPhone = true;
      email = normalizePhone(email);
    }
    // تحقق من بيانات الأدمن من قاعدة البيانات
    if (loginType === 'admin' || (email && email.includes('admin')) || (email && email.includes('tabibIQ'))) {
      let admin = await Admin.findOne({ email: email });
      if (admin) {
        const valid = await bcrypt.compare(password, admin.password);
        if (valid) {
          const adminUser = { 
            email: admin.email, 
            user_type: 'admin', 
            name: admin.name,
            _id: admin._id 
          };
          return res.json({ message: 'تم تسجيل الدخول بنجاح', userType: 'admin', user: adminUser });
        }
      }
      return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
    }
    if (loginType === 'doctor') {
      // تسجيل دخول دكتور - البحث في جدول الأطباء أولاً
      let doctor;
      if (isPhone) {
        doctor = await Doctor.findOne({ phone: email });
      } else {
        doctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
      }
      if (doctor) {
        if (doctor.status !== 'approved') return res.status(403).json({ error: 'لم تتم الموافقة على حسابك بعد من الإدارة' });
        const valid = await bcrypt.compare(password, doctor.password);
        if (!valid) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
        const doctorObj = doctor.toObject();
        doctorObj.user_type = 'doctor';
        return res.json({ message: 'تم تسجيل الدخول بنجاح', userType: 'doctor', doctor: doctorObj });
      }
      // إذا لم يوجد في جدول الأطباء، ابحث في جدول المستخدمين
      let user;
      if (isPhone) {
        user = await User.findOne({ phone: email });
      } else {
        user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
      }
      if (user) {
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
        return res.status(400).json({ error: 'هذا الحساب مسجل كمستخدم عادي وليس كطبيب. يرجى تسجيل الدخول كـ "مستخدم"' });
      }
      return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
    } else {
      // تسجيل دخول مستخدم - البحث في جدول المستخدمين أولاً
      let user;
      if (isPhone) {
        user = await User.findOne({ phone: email });
      } else {
        user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
      }
      if (user) {
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
        const userObj = user.toObject();
        userObj.user_type = 'user';
        return res.json({ message: 'تم تسجيل الدخول بنجاح', userType: 'user', user: userObj });
      }
      // إذا لم يوجد في جدول المستخدمين، ابحث في جدول الأطباء
      let doctor;
      if (isPhone) {
        doctor = await Doctor.findOne({ phone: email });
      } else {
        doctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
      }
      if (doctor) {
        if (doctor.status !== 'approved') return res.status(403).json({ error: 'لم تتم الموافقة على حسابك بعد من الإدارة' });
        const valid = await bcrypt.compare(password, doctor.password);
        if (!valid) return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
        return res.status(400).json({ error: 'هذا الحساب مسجل كطبيب. يرجى تسجيل الدخول كـ "دكتور"' });
      }
      return res.status(400).json({ error: 'بيانات الدخول غير صحيحة' });
    }
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// رفع صورة (مثلاً صورة بروفايل أو رسالة)
app.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي صورة' });
  const imageUrl = `/uploads/${req.file.filename}`;
  res.json({ imageUrl });
});

// عرض الصور مباشرة من السيرفر
app.use('/uploads', express.static(uploadDir));

// رابط إرسال الوثائق على الواتساب
app.get('/send-documents-whatsapp/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const doctor = await Doctor.findById(doctorId);
    
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    const whatsappNumber = '+9647769012619';
    const doctorInfo = `👨‍⚕️ طبيب: ${formatDoctorName(doctor.name)}\n📧 البريد: ${doctor.email}\n📱 الهاتف: ${doctor.phone}\n🏥 التخصص: ${doctor.specialty}\n📍 المحافظة: ${doctor.province}`;
    
    const whatsappMessage = encodeURIComponent(`مرحباً! 👋

${doctorInfo}

📋 المطلوب إرساله:
1️⃣ صورة الهوية الشخصية (الوجه)
2️⃣ صورة الهوية الشخصية (الظهر)  
3️⃣ صورة شهادة النقابة (الوجه)
4️⃣ صورة شهادة النقابة (الظهر)

📞 رقم الهاتف: ${doctor.phone}
📧 البريد الإلكتروني: ${doctor.email}

شكراً لك! 🙏`);

    const whatsappLink = `https://wa.me/${whatsappNumber}?text=${whatsappMessage}`;
    
    res.json({
      whatsappLink: whatsappLink,
      whatsappNumber: whatsappNumber,
      doctorInfo: doctorInfo,
      requiredDocuments: [
        'صورة الهوية الشخصية (الوجه)',
        'صورة الهوية الشخصية (الظهر)',
        'صورة شهادة النقابة (الوجه)',
        'صورة شهادة النقابة (الظهر)'
      ]
    });
    
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء رابط الواتساب' });
  }
});



// جلب مواعيد المستخدم
app.get('/user-appointments/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const appointments = await Appointment.find({ userId })
      .sort({ date: 1, time: 1 })
      .populate('doctorId', 'name specialty province area');
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب مواعيد المستخدم' });
  }
});

// جلب مواعيد الطبيب
app.get('/doctor-appointments/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const doctorObjectId = new mongoose.Types.ObjectId(doctorId);
    

    
    // جلب جميع المواعيد مع إزالة التكرار باستخدام distinct
    const allAppointments = await Appointment.find({ doctorId: doctorObjectId })
      .sort({ date: 1, time: 1 })
      .populate('userId', 'first_name phone')
      .lean(); // تحسين الأداء
    

    
    // إزالة التكرار بناءً على مفتاح فريد يجمع بين التاريخ والوقت واسم المريض ونوع الموعد
    const uniqueMap = new Map();
    allAppointments.forEach(appointment => {
      // استخدام مفتاح فريد يجمع بين التاريخ والوقت واسم المريض ونوع الموعد
      const userName = appointment.userName || (appointment.userId ? appointment.userId.first_name : '') || '';
      const key = `${appointment.date}_${appointment.time}_${userName}_${appointment.type || 'normal'}`;
      
      if (!uniqueMap.has(key)) {
        uniqueMap.set(key, appointment);
      } else {
        // إذا كان هناك تكرار، احتفظ بالموعد الأحدث
        const existing = uniqueMap.get(key);
        if (appointment.createdAt && existing.createdAt) {
          if (new Date(appointment.createdAt) > new Date(existing.createdAt)) {
            uniqueMap.set(key, appointment);
          }
        }
      }
    });
    
    const uniqueAppointments = Array.from(uniqueMap.values());
    
    console.log(`🔍 مواعيد الطبيب ${doctorId}:`);
    console.log(`   - المواعيد الأصلية: ${allAppointments.length}`);
    console.log(`   - المواعيد بعد إزالة التكرار: ${uniqueAppointments.length}`);
    
    res.json(uniqueAppointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب مواعيد الطبيب' });
  }
});

// إرسال رسالة (نصية أو مع صورة)
app.post('/messages', async (req, res) => {
  try {
    const { from, to, text, image } = req.body;
    const message = new Message({ from, to, text, image });
    await message.save();
    res.json({ message: 'تم إرسال الرسالة', msgId: message._id });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إرسال الرسالة' });
  }
});

// جلب الرسائل بين مستخدمين
app.get('/messages', async (req, res) => {
  try {
    const { from, to } = req.query;
    const messages = await Message.find({
      $or: [
        { from: from, to: to },
        { from: to, to: from }
      ]
    }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الرسائل' });
  }
});

// جلب قائمة المستخدمين
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({}, { password: 0, __v: 0 })
      .sort({ createdAt: -1, _id: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب قائمة المستخدمين' });
  }
});

// جلب قائمة الأطباء (الحسابات الرسمية)
app.get('/doctors', async (req, res) => {
  try {
    // جلب الأطباء المميزين أولاً
    const featuredDoctors = await FeaturedDoctor.find({})
      .populate('doctorId', 'name specialty province area image profileImage about workTimes experienceYears phone clinicLocation mapLocation status active createdAt')
      .sort({ priority: -1, createdAt: -1 });
    
    // جلب باقي الأطباء الموافق عليهم
    const regularDoctors = await Doctor.find({ 
      status: 'approved',
      _id: { $nin: featuredDoctors.map(fd => fd.doctorId._id) }
    }, { password: 0, __v: 0 })
      .sort({ createdAt: -1, _id: -1 });

    // دمج النتائج مع إضافة علامة مميز للأطباء المميزين وتنسيق الأسماء
    const featuredDoctorsList = featuredDoctors.map(fd => ({
      ...fd.doctorId.toObject(),
      name: formatDoctorName(fd.doctorId.name), // إضافة "د." تلقائياً
      isFeatured: true,
      featuredPriority: fd.priority
    }));
    
    const regularDoctorsList = regularDoctors.map(doc => ({
      ...doc.toObject(),
      name: formatDoctorName(doc.name), // إضافة "د." تلقائياً
      isFeatured: false
    }));

    // دمج القائمتين مع الأطباء المميزين في المقدمة
    const allDoctors = [...featuredDoctorsList, ...regularDoctorsList];

    res.json(allDoctors);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب قائمة الأطباء' });
  }
});

// جلب جميع الأطباء (للإدارة - يشمل المعلقين مع جميع البيانات)
app.get('/admin/doctors', async (req, res) => {
  try {
    const allDoctors = await Doctor.find({}, { password: 0, __v: 0 })
      .populate('centerId', 'name type')
      .sort({ createdAt: -1, _id: -1 });
    
    // إضافة URLs كاملة للصور والوثائق مباشرة وتنسيق الأسماء
    const doctorsWithFullUrls = allDoctors.map(doctor => {
      const doctorObj = doctor.toObject();
      const baseUrl = req.protocol + '://' + req.get('host');
      
      // تنسيق اسم الطبيب
      doctorObj.name = formatDoctorName(doctorObj.name);
      // إضافة URLs كاملة للصور والوثائق مباشرة
      if (doctorObj.image) {
        doctorObj.imageUrl = `${baseUrl}${doctorObj.image}`;
      }
      if (doctorObj.idFront) {
        doctorObj.idFrontUrl = `${baseUrl}${doctorObj.idFront}`;
      }
      if (doctorObj.idBack) {
        doctorObj.idBackUrl = `${baseUrl}${doctorObj.idBack}`;
      }
      if (doctorObj.syndicateFront) {
        doctorObj.syndicateFrontUrl = `${baseUrl}${doctorObj.syndicateFront}`;
      }
      if (doctorObj.syndicateBack) {
        doctorObj.syndicateBackUrl = `${baseUrl}${doctorObj.syndicateBack}`;
      }
      
      // إضافة معلومات إضافية مفيدة للإدارة
      doctorObj.createdAtFormatted = new Date(doctorObj.createdAt).toLocaleDateString('ar-EG', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
      
      // إضافة حالة مقروءة
      doctorObj.statusText = {
        'pending': 'في انتظار المراجعة',
        'approved': 'تمت الموافقة',
        'rejected': 'مرفوض'
      }[doctorObj.status] || 'غير محدد';
      
      return doctorObj;
    });
    
    res.json(doctorsWithFullUrls);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب قائمة الأطباء' });
  }
});

// ========== API التخصصات والمحافظات ==========

// جلب جميع التخصصات الطبية
app.get('/specialties', async (req, res) => {
  try {
    const Specialty = mongoose.model('Specialty', new mongoose.Schema({
      name: { type: String, required: true, unique: true },
      description: String,
      active: { type: Boolean, default: true },
      createdAt: { type: Date, default: Date.now }
    }));
    
    const specialties = await Specialty.find({ active: true }).sort({ name: 1 });
    res.json(specialties);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب التخصصات' });
  }
});

// جلب جميع محافظات العراق
app.get('/provinces', async (req, res) => {
  try {
    const Province = mongoose.model('Province', new mongoose.Schema({
      name: { type: String, required: true, unique: true },
      active: { type: Boolean, default: true },
      createdAt: { type: Date, default: Date.now }
    }));
    
    const provinces = await Province.find({ active: true }).sort({ name: 1 });
    res.json(provinces);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المحافظات' });
  }
});

// ========== API المراكز الصحية ==========

// تسجيل مركز صحي جديد (للأدمن فقط)
app.post('/admin/health-centers', async (req, res) => {
  try {
    const { name, email, password, phone, type, description, location, services, specialties, doctors } = req.body;
    
    // التحقق من البيانات المطلوبة
    if (!name || !email || !password || !phone) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // التحقق من عدم وجود مركز بنفس البريد الإلكتروني
    const existingCenter = await HealthCenter.findOne({ email });
    if (existingCenter) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
    }
    
    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // معالجة الأطباء إذا وجدوا
    let processedDoctors = [];
    if (doctors && Array.isArray(doctors)) {
      processedDoctors = doctors.map(doctor => ({
        name: formatDoctorName(doctor.name), // إضافة "د." تلقائياً
        specialty: doctor.specialty,
        experience: doctor.experience,
        education: doctor.education,
        workingHours: doctor.workingHours,
        description: doctor.description,
        phone: doctor.phone,
        email: doctor.email
      }));
    }
    
    // إنشاء المركز الجديد
    const newCenter = new HealthCenter({
      name,
      email,
      password: hashedPassword,
      phone,
      type: type || 'health_center',
      description,
      location,
      services: services || [],
      specialties: specialties || [],
      doctors: processedDoctors,
      status: 'approved' // الموافقة المباشرة من الأدمن
    });
    
    await newCenter.save();
    
    res.status(201).json({ 
      message: 'تم إنشاء المركز الصحي بنجاح',
      center: {
        id: newCenter._id,
        name: newCenter.name,
        email: newCenter.email,
        type: newCenter.type,
        doctors: newCenter.doctors
      }
    });
    
  } catch (err) {
    console.error('خطأ في إنشاء المركز الصحي:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء المركز الصحي' });
  }
});

// جلب جميع المراكز الصحية (للأدمن)
app.get('/admin/health-centers', async (req, res) => {
  try {
    const centers = await HealthCenter.find({}, { password: 0, __v: 0 })
      .sort({ createdAt: -1 });
    
    res.json(centers);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المراكز الصحية' });
  }
});

// إضافة طبيب لمركز صحي
app.post('/admin/health-centers/:centerId/doctors', async (req, res) => {
  try {
    const { centerId } = req.params;
    const { name, specialty, experience, education, workingHours, description, phone, email } = req.body;
    
    // التحقق من البيانات المطلوبة
    if (!name || !specialty || !email) {
      return res.status(400).json({ error: 'الاسم والتخصص والبريد الإلكتروني مطلوبة' });
    }
    
    // البحث عن المركز
    const center = await HealthCenter.findById(centerId);
    if (!center) {
      return res.status(404).json({ error: 'المركز الصحي غير موجود' });
    }
    
    // إضافة الطبيب للمركز
    const newDoctor = {
      name: formatDoctorName(name), // إضافة "د." تلقائياً
      specialty,
      experience: experience || '',
      education: education || '',
      workingHours: workingHours || '',
      description: description || '',
      phone: phone || '',
      email
    };
    
    center.doctors.push(newDoctor);
    await center.save();
    
    res.status(201).json({ 
      message: 'تم إضافة الطبيب بنجاح',
      doctor: newDoctor
    });
    
  } catch (err) {
    console.error('خطأ في إضافة الطبيب:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء إضافة الطبيب' });
  }
});

// تسجيل دخول المركز الصحي
app.post('/center/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }
    
    // البحث عن المركز
    const center = await HealthCenter.findOne({ email });
    if (!center) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }
    
    // التحقق من حالة المركز
    if (center.status !== 'approved') {
      return res.status(401).json({ error: 'حساب المركز لم تتم الموافقة عليه بعد' });
    }
    
    // التحقق من كلمة المرور
    const isValidPassword = await bcrypt.compare(password, center.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
    }
    
    // إرسال بيانات المركز (بدون كلمة المرور)
    const centerData = {
      id: center._id,
      name: center.name,
      email: center.email,
      type: center.type,
      phone: center.phone,
      location: center.location,
      services: center.services,
      specialties: center.specialties,
      doctors: center.doctors,
      status: center.status
    };
    
    res.json({ 
      message: 'تم تسجيل الدخول بنجاح',
      center: centerData
    });
    
  } catch (err) {
    console.error('خطأ في تسجيل دخول المركز:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// جلب بيانات مركز صحي مع أطبائه
app.get('/center/:centerId', async (req, res) => {
  try {
    const { centerId } = req.params;
    
    const center = await HealthCenter.findById(centerId)
      .populate('doctors', 'name specialty image about experienceYears')
      .select('-password -__v');
    
    if (!center) {
      return res.status(404).json({ error: 'المركز الصحي غير موجود' });
    }
    const baseUrl = req.protocol + '://' + req.get('host');
// إضافة URLs للصور
const centerData = center.toObject();
if (centerData.images && centerData.images.logo) {
  centerData.images.logoUrl = `${baseUrl}${centerData.images.logo}`;
}
if (centerData.images && centerData.images.cover) {
  centerData.images.coverUrl = `${baseUrl}${centerData.images.cover}`;
}

// إضافة URLs لصور الأطباء
if (centerData.doctors) {
  centerData.doctors = centerData.doctors.map(doctor => {
    if (doctor.image) {
      doctor.imageUrl = `${baseUrl}${doctor.image}`;
    }
    return doctor;
  });
}
    
    res.json(centerData);
    
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب بيانات المركز' });
  }
});

// جلب جميع المراكز الصحية المعتمدة (للمستخدمين)
app.get('/health-centers', async (req, res) => {
  try {
    const centers = await HealthCenter.find({ 
      status: 'approved', 
      active: true 
    })
    .populate('doctors', 'name specialty image')
    .select('-password -__v')
    .sort({ is_featured: -1, rating: -1 });
    
    // إضافة URLs للصور
   const baseUrl = req.protocol + '://' + req.get('host');
const centersWithUrls = centers.map(center => {
  const centerData = center.toObject();
  if (centerData.images && centerData.images.logo) {
    centerData.images.logoUrl = `${baseUrl}${centerData.images.logo}`;
  }
  if (centerData.images && centerData.images.cover) {
    centerData.images.coverUrl = `${baseUrl}${centerData.images.cover}`;
  }
  
  // إضافة URLs لصور الأطباء
  if (centerData.doctors) {
    centerData.doctors = centerData.doctors.map(doctor => {
      if (doctor.image) {
        doctor.imageUrl = `${baseUrl}${doctor.image}`;
      }
      return doctor;
    });
  }
  
  return centerData;
});
    
    res.json(centersWithUrls);
    
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المراكز الصحية' });
  }
});



// نقطة نهائية لاختبار الاتصال وإضافة بيانات تجريبية
app.get('/test-db', async (req, res) => {
  try {
    // التحقق من الاتصال
    const dbState = mongoose.connection.readyState;

    
    // إضافة طبيب تجريبي إذا لم يكن موجود
    const existingDoctor = await Doctor.findOne({ email: 'test@doctor.com' });
    if (!existingDoctor) {
      const testDoctor = new Doctor({
        email: 'test@doctor.com',
        password: 'hashedpassword',
        name: 'د. أحمد محمد',
        phone: '07701234567',
        specialty: 'طب عام',
        province: 'بغداد',
        area: 'الكرادة',
        clinicLocation: 'شارع الرشيد، بغداد',
        about: 'طبيب عام ذو خبرة 10 سنوات',
        status: 'approved',
        active: true
      });
      await testDoctor.save();
  
    }
    
    // جلب جميع الأطباء
    const allDoctors = await Doctor.find({});
    
    // جلب جميع الإشعارات
    const allNotifications = await Notification.find({});
    
    // جلب جميع المواعيد
    const allAppointments = await Appointment.find({});
    
    res.json({
      connectionState: dbState,
      totalDoctors: allDoctors.length,
      approvedDoctors: allDoctors.filter(d => d.status === 'approved').length,
      totalNotifications: allNotifications.length,
      totalAppointments: allAppointments.length,
      doctors: allDoctors.map(d => ({ id: d._id, name: d.name, email: d.email, status: d.status })),
      notifications: allNotifications.map(n => ({ id: n._id, type: n.type, message: n.message, doctorId: n.doctorId, userId: n.userId })),
      appointments: allAppointments.map(a => ({ id: a._id, doctorId: a.doctorId, userId: a.userId, date: a.date, time: a.time }))
    });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في اختبار قاعدة البيانات', details: err.message });
  }
});

// جلب الأطباء بانتظار الموافقة (مع ترتيب وحد أقصى ودعم skip)
app.get('/pending-doctors', async (req, res) => {
  try {
    const limit = 30;
    const skip = parseInt(req.query.skip) || 0;
    const doctors = await Doctor.find({ status: 'pending' }, { password: 0, __v: 0 })
      .sort({ createdAt: -1, _id: -1 })
      .skip(skip)
      .limit(limit);
    res.json(doctors);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب طلبات الأطباء' });
  }
});

// حجز موعد جديد
app.post('/appointments', async (req, res) => {
  try {
    const { userId, doctorId, userName, doctorName, date, time, reason, duration } = req.body;
    if (!userId || !doctorId || !date || !time) {
      return res.status(400).json({ error: 'البيانات ناقصة' });
    }
    

    
    // التحقق من وجود موعد مكرر قبل الإنشاء
    const existingAppointment = await Appointment.findOne({
      userId: userId,
      doctorId: new mongoose.Types.ObjectId(doctorId),
      date: date,
      time: time
    });
    
    if (existingAppointment) {
      return res.status(400).json({ error: 'هذا الموعد محجوز مسبقاً' });
    }
    
    const appointment = new Appointment({
      userId,
      doctorId: new mongoose.Types.ObjectId(doctorId),
      userName,
      doctorName: formatDoctorName(doctorName), // إضافة "د." تلقائياً
      date,
      time,
      reason,
      duration: duration ? Number(duration) : 30 // مدة الموعد بالدقائق
    });
    await appointment.save();

    
    // إشعار للدكتور عند حجز موعد جديد
    try {
      const notification = await Notification.create({
        doctorId: new mongoose.Types.ObjectId(doctorId),
        type: 'new_appointment',
        message: `تم حجز موعد جديد من قبل ${userName} في ${date} الساعة ${time}`
      });

    } catch (notificationError) {
      // لا نوقف العملية إذا فشل إنشاء الإشعار
    }
    
    res.json({ message: 'تم حجز الموعد بنجاح', appointment });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حجز الموعد' });
  }
});

// جلب المواعيد المحجوزة لطبيب معين في تاريخ محدد
app.get('/appointments/:doctorId/:date', async (req, res) => {
  try {
    const { doctorId, date } = req.params;
    const appointments = await Appointment.find({
      doctorId: doctorId,
      date: date
    });
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المواعيد المحجوزة' });
  }
});

// جلب مواعيد المستخدم
app.get('/user-appointments/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const appointments = await Appointment.find({ userId: userId })
      .sort({ date: 1, time: 1 }); // ترتيب حسب التاريخ والوقت
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب مواعيد المستخدم' });
  }
});

// جلب مواعيد الدكتور
app.get('/doctor-appointments/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const doctorObjectId = new mongoose.Types.ObjectId(doctorId);
    

    
    // جلب جميع المواعيد مع إزالة التكرار باستخدام distinct
    const allAppointments = await Appointment.find({ doctorId: doctorObjectId })
      .sort({ date: 1, time: 1 })
      .populate('userId', 'first_name phone')
      .lean(); // تحسين الأداء
    

    
    // إزالة التكرار بناءً على مفتاح فريد يجمع بين التاريخ والوقت واسم المريض ونوع الموعد
    const uniqueMap = new Map();
    allAppointments.forEach(appointment => {
      // استخدام مفتاح فريد يجمع بين التاريخ والوقت واسم المريض ونوع الموعد
      const userName = appointment.userName || (appointment.userId ? appointment.userId.first_name : '') || '';
      const key = `${appointment.date}_${appointment.time}_${userName}_${appointment.type || 'normal'}`;
      
      if (!uniqueMap.has(key)) {
        uniqueMap.set(key, appointment);
      } else {
        // إذا كان هناك تكرار، احتفظ بالموعد الأحدث
        const existing = uniqueMap.get(key);
        if (appointment.createdAt && existing.createdAt) {
          if (new Date(appointment.createdAt) > new Date(existing.createdAt)) {
            uniqueMap.set(key, appointment);
          }
        }
      }
    });
    
    const uniqueAppointments = Array.from(uniqueMap.values());
    
    console.log(`🔍 مواعيد الطبيب ${doctorId}:`);
    console.log(`   - المواعيد الأصلية: ${allAppointments.length}`);
    console.log(`   - المواعيد بعد إزالة التكرار: ${uniqueAppointments.length}`);
    
    res.json(uniqueAppointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب مواعيد الطبيب' });
  }
});

// إلغاء موعد
app.delete('/appointments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const appointment = await Appointment.findByIdAndDelete(id);
    
    if (!appointment) {
      return res.status(404).json({ error: 'الموعد غير موجود' });
    }
    
    res.json({ message: 'تم إلغاء الموعد بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إلغاء الموعد' });
  }
});

// تحديث موعد
app.put('/appointments/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    const appointment = await Appointment.findByIdAndUpdate(
      id, 
      updateData, 
      { new: true, runValidators: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ error: 'الموعد غير موجود' });
    }
    
    res.json({ 
      success: true, 
      message: 'تم تحديث الموعد بنجاح', 
      appointment 
    });
  } catch (err) {
    console.error('خطأ في تحديث الموعد:', err);
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء تحديث الموعد',
      details: err.message 
    });
  }
});

// تحديث بيانات المستخدم
app.put('/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateFields = { ...req.body };
    const user = await User.findByIdAndUpdate(id, updateFields, { new: true });
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم تحديث البيانات بنجاح', user });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث البيانات' });
  }
});

// تحديث بيانات الطبيب
app.put('/doctor/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // فحص البريد الإلكتروني إذا تم تغييره
    if (req.body.email) {
      const existingDoctor = await Doctor.findOne({ 
        email: req.body.email, 
        _id: { $ne: id } // استثناء الطبيب الحالي
      });
      
      if (existingDoctor) {
        return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقاً' });
      }
    }
    
    // استخدم كل الحقول المرسلة في body
    const updateFields = { ...req.body };
    
    const doctor = await Doctor.findByIdAndUpdate(id, updateFields, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    
    // تأكد من وجود user_type
    if (!doctor.user_type) doctor.user_type = 'doctor';
    res.json({ message: 'تم تحديث البيانات بنجاح', doctor });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث البيانات' });
  }
});

// تفعيل/توقيف حساب دكتور
app.put('/doctor-active/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { active } = req.body;
    const doctor = await Doctor.findByIdAndUpdate(id, { active }, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم تحديث حالة الحساب بنجاح', doctor });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الحساب' });
  }
});

// تغيير كلمة مرور دكتور
app.put('/doctor-password/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const doctor = await Doctor.findByIdAndUpdate(id, { password: hashed }, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم تغيير كلمة المرور بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تغيير كلمة المرور' });
  }
});

// حذف دكتور
app.delete('/doctor/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const doctor = await Doctor.findByIdAndDelete(id);
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم حذف الحساب بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حذف الحساب' });
  }
});

// تفعيل/توقيف حساب مستخدم
app.put('/user-active/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { active } = req.body;
    const user = await User.findByIdAndUpdate(id, { active }, { new: true });
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم تحديث حالة الحساب بنجاح', user });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الحساب' });
  }
});

// تغيير كلمة مرور مستخدم
app.put('/user-password/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.findByIdAndUpdate(id, { password: hashed }, { new: true });
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم تغيير كلمة المرور بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تغيير كلمة المرور' });
  }
});

// حذف مستخدم
app.delete('/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم حذف الحساب بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حذف الحساب' });
  }
});

// جلب جميع المواعيد
app.get('/all-appointments', async (req, res) => {
  try {
    const appointments = await Appointment.find({})
      .populate('userId', 'first_name phone')
      .populate('doctorId', 'name specialty province area')
      .sort({ createdAt: -1 });
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المواعيد' });
  }
});

// تحديث حالة طبيب (موافقة/رفض)
app.put('/doctor-status/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const doctor = await Doctor.findByIdAndUpdate(id, { status }, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم تحديث حالة الطبيب بنجاح', doctor });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الطبيب' });
  }
});

// تحديث حالة دكتور (موافقة/رفض)
app.put('/doctor-status/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'حالة غير صالحة' });
    const doctor = await Doctor.findByIdAndUpdate(id, { status }, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم تحديث حالة الطبيب', doctor });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الطبيب' });
  }
});

// توقيف/تفعيل حساب دكتور
app.put('/doctor-active/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { active } = req.body;
    const doctor = await Doctor.findByIdAndUpdate(id, { active }, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: active ? 'تم تفعيل الحساب' : 'تم توقيف الحساب', doctor });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الحساب' });
  }
});
// تغيير كلمة مرور دكتور من الأدمن
app.put('/doctor-password/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const doctor = await Doctor.findByIdAndUpdate(id, { password: hashed }, { new: true });
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم تغيير كلمة المرور بنجاح', doctor });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تغيير كلمة المرور' });
  }
});
// حذف حساب دكتور نهائياً
app.delete('/doctor/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const doctor = await Doctor.findByIdAndDelete(id);
    if (!doctor) return res.status(404).json({ error: 'الطبيب غير موجود' });
    res.json({ message: 'تم حذف الحساب بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حذف الحساب' });
  }
});

// جلب جميع المستخدمين
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({}, { password: 0, __v: 0 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المستخدمين' });
  }
});

// جلب جميع المواعيد
app.get('/all-appointments', async (req, res) => {
  try {
    const appointments = await Appointment.find({})
      .populate('userId', 'first_name email phone')
      .populate('doctorId', 'name specialty province area');
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المواعيد' });
  }
});

// توقيف/تفعيل حساب مستخدم
app.put('/user-active/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { active } = req.body;
    const user = await User.findByIdAndUpdate(id, { active }, { new: true });
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: active ? 'تم تفعيل الحساب' : 'تم توقيف الحساب', user });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الحساب' });
  }
});
// تغيير كلمة مرور مستخدم من الأدمن
app.put('/user-password/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.findByIdAndUpdate(id, { password: hashed }, { new: true });
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم تغيير كلمة المرور بنجاح', user });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تغيير كلمة المرور' });
  }
});
// حذف حساب مستخدم نهائياً
app.delete('/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
    res.json({ message: 'تم حذف الحساب بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حذف الحساب' });
  }
});

// جلب إشعارات مستخدم أو دكتور
app.get('/notifications', async (req, res) => {
  try {
    const { userId, doctorId } = req.query;
    let filter = {};
    if (userId) filter.userId = userId;
    if (doctorId) filter.doctorId = doctorId;
    
    const notifications = await Notification.find(filter).sort({ createdAt: -1 }).limit(50);
    
    res.json(notifications);
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الإشعارات' });
  }
});

// نقطة نهائية لاختبار إنشاء إشعار
app.post('/test-notification', async (req, res) => {
  try {
    const { doctorId, message } = req.body;
    
    if (!doctorId || !message) {
      return res.status(400).json({ error: 'doctorId و message مطلوبان' });
    }
    

    
    // التحقق من وجود الطبيب أولاً
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    

    
    const notification = await Notification.create({
      doctorId: new mongoose.Types.ObjectId(doctorId),
      type: 'test',
      message: message
    });
    

    res.json({ message: 'تم إنشاء الإشعار التجريبي بنجاح', notification });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الإشعار التجريبي', details: err.message });
  }
});

// نقطة نهائية لفحص قاعدة البيانات مباشرة
app.get('/debug-db', async (req, res) => {
  try {
    // فحص جميع المجموعات
    const collections = await mongoose.connection.db.listCollections().toArray();
    
    // فحص الإشعارات
    const notifications = await Notification.find({});
    
    // فحص الأطباء
    const doctors = await Doctor.find({});
    
    // فحص المواعيد
    const appointments = await Appointment.find({});
    
    res.json({
      collections: collections.map(c => c.name),
      notifications: notifications,
      doctors: doctors.map(d => ({ id: d._id, name: d.name, email: d.email })),
      appointments: appointments.map(a => ({ id: a._id, doctorId: a.doctorId, userId: a.userId }))
    });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في فحص قاعدة البيانات', details: err.message });
  }
});



// تعليم كل إشعارات الدكتور كمقروءة
app.put('/notifications/mark-read', async (req, res) => {
  try {
    const { doctorId, userId } = req.query;
    let filter = {};
    if (doctorId) filter.doctorId = doctorId;
    if (userId) filter.userId = userId;
    await Notification.updateMany(filter, { $set: { read: true } });
    res.json({ message: 'تم تعليم الإشعارات كمقروءة' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تعليم الإشعارات كمقروءة' });
  }
});

// إرسال إشعار للمريض
app.post('/send-notification', async (req, res) => {
  try {
    const { phone, message, type, userId, doctorId, appointmentData } = req.body;
    

    
    // إنشاء الإشعار في قاعدة البيانات
    const notification = new Notification({
      userId: userId ? new mongoose.Types.ObjectId(userId) : null,
      doctorId: doctorId ? new mongoose.Types.ObjectId(doctorId) : null,
      type: type || 'general',
      message: message,
      read: false
    });
    
    await notification.save();

    
    // هنا يمكن إضافة منطق إرسال SMS أو push notification
    // محاكاة إرسال SMS
    // console.log(`📱 SMS to ${phone}: ${message}`);
    
    // محاكاة إرسال push notification
    // console.log(`🔔 Push notification: ${message}`);
    
    res.json({ 
      success: true, 
      message: 'تم إرسال الإشعار بنجاح',
      notification: {
        id: notification._id,
        type: notification.type,
        message: notification.message,
        createdAt: notification.createdAt
      }
    });
  } catch (err) {
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء إرسال الإشعار',
      details: err.message 
    });
  }
});

// إرسال إشعار موعد خاص
app.post('/send-special-appointment-notification', async (req, res) => {
  try {
    const { 
      patientPhone, 
      patientName, 
      originalAppointmentId, 
      newDate, 
      newTime, 
      doctorName,
      doctorId,
      reason,
      notes 
    } = req.body;
    const normPhone = normalizePhone(patientPhone);
    const user = await User.findOne({ phone: normPhone });
    let userId = null;
    if (user) userId = user._id;
    const message = `مرحباً ${patientName}، تم تحويل موعدك إلى موعد خاص في ${newDate} الساعة ${newTime}. السبب: ${reason || 'غير محدد'}. ${notes ? `ملاحظات: ${notes}` : ''}`;
    // إضافة الموعد الخاص في جدول المواعيد إذا كان المستخدم موجود
    if (userId && doctorId) {
      await Appointment.create({
        userId,
        doctorId,
        userName: patientName,
        doctorName,
        date: newDate,
        time: newTime,
        reason: reason ? `موعد خاص: ${reason}` : 'موعد خاص',
        type: 'special_appointment',
        createdAt: new Date()
      });
    }
    const notifyTime = new Date(new Date(`${newDate}T${newTime}`).getTime() - 5 * 60 * 1000);
    const now = new Date();
    const delay = notifyTime - now;
    if (delay > 0) {
      setTimeout(async () => {
        try {
          const notification = new Notification({
            userId: userId,
            type: 'special_appointment',
            message: message,
            read: false
          });
          await notification.save();
        } catch (e) {}
      }, delay);
      res.json({ 
        success: true, 
        message: 'سيتم إرسال إشعار الموعد الخاص قبل الموعد بـ 5 دقائق',
        notifyAt: notifyTime
      });
    } else {
      const notification = new Notification({
        userId: userId,
        type: 'special_appointment',
        message: message,
        read: false
      });
      await notification.save();
      res.json({ 
        success: true, 
        message: 'تم إرسال إشعار الموعد الخاص مباشرة (لأن الوقت قريب جداً)',
        notification: {
          message: notification.message,
          type: notification.type
        }
      });
    }
  } catch (err) {
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء إرسال إشعار الموعد الخاص',
      details: err.message 
    });
  }
});

// إرسال إشعار تذكير الدواء
app.post('/send-medicine-reminder', async (req, res) => {
  try {
    const { 
      userId,
      medicineName,
      dosage,
      time,
      phone 
    } = req.body;
    
    const message = `⏰ تذكير: حان وقت تناول ${medicineName} - ${dosage}`;
    

    
    // إنشاء الإشعار
    const notification = new Notification({
      userId: userId ? new mongoose.Types.ObjectId(userId) : null,
      type: 'medicine_reminder',
      message: message,
      read: false
    });
    
    await notification.save();
    
    // محاكاة إرسال SMS
    // console.log(`💊 Medicine reminder SMS to ${phone}: ${message}`);
    
    res.json({ 
      success: true, 
      message: 'تم إرسال تذكير الدواء بنجاح',
      notification: {
        id: notification._id,
        message: notification.message,
        type: notification.type
      }
    });
  } catch (err) {
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء إرسال تذكير الدواء',
      details: err.message 
    });
  }
});

// ===== API للأطباء المميزين =====

// جلب جميع الأطباء المميزين
app.get('/featured-doctors', async (req, res) => {
  try {
    const featuredDoctors = await FeaturedDoctor.find({})
      .populate('doctorId', 'name specialty province area image profileImage about workTimes experienceYears phone clinicLocation mapLocation status active createdAt')
      .sort({ priority: -1, createdAt: -1 });
    
    res.json(featuredDoctors);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الأطباء المميزين' });
  }
});

// إضافة طبيب للمميزين
app.post('/featured-doctors', async (req, res) => {
  try {
    const { doctorId } = req.body;
    
    if (!doctorId) {
      return res.status(400).json({ error: 'معرف الطبيب مطلوب' });
    }
    
    // التحقق من وجود الطبيب
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    // التحقق من عدم وجود الطبيب في المميزين مسبقاً
    const existingFeatured = await FeaturedDoctor.findOne({ doctorId });
    if (existingFeatured) {
      return res.status(400).json({ error: 'الطبيب موجود في المميزين مسبقاً' });
    }
    
    // إضافة الطبيب للمميزين
    const featuredDoctor = new FeaturedDoctor({ doctorId });
    await featuredDoctor.save();
    
    res.json({ 
      message: 'تم إضافة الطبيب للمميزين بنجاح',
      featuredDoctor 
    });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إضافة الطبيب للمميزين' });
  }
});

// إزالة طبيب من المميزين
app.delete('/featured-doctors/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    
    const result = await FeaturedDoctor.findOneAndDelete({ doctorId });
    
    if (!result) {
      return res.status(404).json({ error: 'الطبيب غير موجود في المميزين' });
    }
    
    res.json({ message: 'تم إزالة الطبيب من المميزين بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إزالة الطبيب من المميزين' });
  }
});

// تحديث أولوية الطبيب المميز
app.put('/featured-doctors/:doctorId/priority', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const { priority } = req.body;
    
    const featuredDoctor = await FeaturedDoctor.findOneAndUpdate(
      { doctorId },
      { priority: priority || 0 },
      { new: true }
    );
    
    if (!featuredDoctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود في المميزين' });
    }
    
    res.json({ 
      message: 'تم تحديث أولوية الطبيب بنجاح',
      featuredDoctor 
    });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث أولوية الطبيب' });
  }
});

// ===== API للتحليل الشامل للأطباء =====

// تحليل شامل للأطباء
app.get('/doctors-analytics', async (req, res) => {
  try {
    // إحصائيات عامة
    const totalDoctors = await Doctor.countDocuments();
    const activeDoctors = await Doctor.countDocuments({ active: true });
    const pendingDoctors = await Doctor.countDocuments({ status: 'pending' });
    const approvedDoctors = await Doctor.countDocuments({ status: 'approved' });
    const rejectedDoctors = await Doctor.countDocuments({ status: 'rejected' });
    const featuredDoctorsCount = await FeaturedDoctor.countDocuments();

    // إحصائيات المواعيد لكل طبيب
    const appointmentsByDoctor = await Appointment.aggregate([
      {
        $group: {
          _id: '$doctorId',
          appointmentCount: { $sum: 1 },
          uniquePatients: { $addToSet: '$userId' }
        }
      },
      {
        $lookup: {
          from: 'doctors',
          localField: '_id',
          foreignField: '_id',
          as: 'doctorInfo'
        }
      },
      {
        $unwind: '$doctorInfo'
      },
      {
        $project: {
          doctorId: '$_id',
          doctorName: '$doctorInfo.name',
          specialty: '$doctorInfo.specialty',
          province: '$doctorInfo.province',
          appointmentCount: 1,
          uniquePatientsCount: { $size: '$uniquePatients' },
          isFeatured: { $in: ['$_id', { $ifNull: ['$featuredDoctors', []] }] }
        }
      },
      {
        $sort: { appointmentCount: -1 }
      }
    ]);

    // إحصائيات حسب التخصص
    const specialtyStats = await Doctor.aggregate([
      {
        $group: {
          _id: '$specialty',
          count: { $sum: 1 },
          activeCount: {
            $sum: { $cond: ['$active', 1, 0] }
          }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    // إحصائيات حسب المحافظة
    const provinceStats = await Doctor.aggregate([
      {
        $group: {
          _id: '$province',
          count: { $sum: 1 },
          activeCount: {
            $sum: { $cond: ['$active', 1, 0] }
          }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    // الأطباء الأكثر نشاطاً (أعلى عدد مواعيد)
    const mostActiveDoctors = appointmentsByDoctor.slice(0, 10);

    // الأطباء الأقل نشاطاً
    const leastActiveDoctors = appointmentsByDoctor
      .filter(doc => doc.appointmentCount > 0)
      .slice(-10)
      .reverse();

    // إحصائيات المواعيد الشهرية
    const monthlyAppointments = await Appointment.aggregate([
      {
        $addFields: {
          month: { $month: '$createdAt' },
          year: { $year: '$createdAt' }
        }
      },
      {
        $group: {
          _id: { month: '$month', year: '$year' },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': -1, '_id.month': -1 }
      },
      {
        $limit: 12
      }
    ]);

    // إحصائيات المواعيد اليومية (آخر 30 يوم)
    const dailyAppointments = await Appointment.aggregate([
      {
        $match: {
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        }
      },
      {
        $addFields: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
        }
      },
      {
        $group: {
          _id: '$date',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: -1 }
      }
    ]);

    // الأطباء المميزين مع إحصائياتهم
    const featuredDoctorsWithStats = await FeaturedDoctor.aggregate([
      {
        $lookup: {
          from: 'doctors',
          localField: 'doctorId',
          foreignField: '_id',
          as: 'doctorInfo'
        }
      },
      {
        $unwind: '$doctorInfo'
      },
      {
        $lookup: {
          from: 'appointments',
          localField: 'doctorId',
          foreignField: 'doctorId',
          as: 'appointments'
        }
      },
      {
        $project: {
          doctorId: '$doctorId',
          doctorName: '$doctorInfo.name',
          specialty: '$doctorInfo.specialty',
          province: '$doctorInfo.province',
          priority: '$priority',
          appointmentCount: { $size: '$appointments' },
          isActive: '$doctorInfo.active'
        }
      },
      {
        $sort: { priority: -1, appointmentCount: -1 }
      }
    ]);

    res.json({
      success: true,
      analytics: {
        overview: {
          totalDoctors,
          activeDoctors,
          pendingDoctors,
          approvedDoctors,
          rejectedDoctors,
          featuredDoctorsCount
        },
        appointmentsByDoctor,
        specialtyStats,
        provinceStats,
        mostActiveDoctors,
        leastActiveDoctors,
        monthlyAppointments,
        dailyAppointments,
        featuredDoctorsWithStats
      }
    });
  } catch (err) {
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء جلب التحليل',
      details: err.message 
    });
  }
});

// تحليل طبيب محدد
app.get('/doctor-analytics/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    
    // معلومات الطبيب
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }

    // إحصائيات المواعيد
    const appointments = await Appointment.find({ doctorId });
    const totalAppointments = appointments.length;
    const uniquePatients = [...new Set(appointments.map(a => a.userId.toString()))].length;

    // المواعيد الشهرية (آخر 12 شهر)
    const monthlyAppointments = await Appointment.aggregate([
      { $match: { doctorId: new mongoose.Types.ObjectId(doctorId) } },
      {
        $addFields: {
          month: { $month: '$createdAt' },
          year: { $year: '$createdAt' }
        }
      },
      {
        $group: {
          _id: { month: '$month', year: '$year' },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': -1, '_id.month': -1 }
      },
      {
        $limit: 12
      }
    ]);

    // المواعيد اليومية (آخر 30 يوم)
    const dailyAppointments = await Appointment.aggregate([
      { 
        $match: { 
          doctorId: new mongoose.Types.ObjectId(doctorId),
          createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
        } 
      },
      {
        $addFields: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
        }
      },
      {
        $group: {
          _id: '$date',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { _id: -1 }
      }
    ]);

    // التحقق من كون الطبيب مميز
    const isFeatured = await FeaturedDoctor.findOne({ doctorId });
    const featuredPriority = isFeatured ? isFeatured.priority : null;

    res.json({
      success: true,
      doctor: {
        _id: doctor._id,
        name: formatDoctorName(doctor.name), // إضافة "د." تلقائياً
        specialty: doctor.specialty,
        province: doctor.province,
        area: doctor.area,
        active: doctor.active,
        status: doctor.status,
        experienceYears: doctor.experienceYears,
        isFeatured: !!isFeatured,
        featuredPriority
      },
      analytics: {
        totalAppointments,
        uniquePatients,
        monthlyAppointments,
        dailyAppointments
      }
    });
  } catch (err) {
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء جلب تحليل الطبيب',
      details: err.message 
    });
  }
});

// ==================== APIs للأدمن ====================

// جلب جميع المستخدمين
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({ active: true })
      .select('first_name email phone createdAt')
      .sort({ createdAt: -1 });
    
    const formattedUsers = users.map(user => ({
      id: user._id,
      name: user.first_name,
      email: user.email,
      phone: user.phone,
      created_at: user.createdAt.toISOString().split('T')[0]
    }));
    
    res.json(formattedUsers);
  } catch (error) {
    res.status(500).json({ error: 'خطأ في جلب المستخدمين' });
  }
});

// حذف مستخدم
app.delete('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    await User.findByIdAndUpdate(userId, { active: false });
    res.json({ message: 'تم حذف المستخدم بنجاح' });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في حذف المستخدم' });
  }
});

// جلب جميع الأطباء
app.get('/api/doctors', async (req, res) => {
  try {
    const doctors = await Doctor.find()
      .select('name email specialty status active createdAt is_featured')
      .sort({ createdAt: -1 });
    
    const formattedDoctors = doctors.map(doctor => ({
      id: doctor._id,
      name: formatDoctorName(doctor.name), // إضافة "د." تلقائياً
      email: doctor.email,
      specialty: doctor.specialty,
      status: doctor.status === 'approved' ? 'active' : 'pending',
      is_featured: doctor.is_featured || false,
      created_at: doctor.createdAt ? doctor.createdAt.toISOString().split('T')[0] : 'غير محدد'
    }));
    
    res.json(formattedDoctors);
  } catch (error) {
    console.error('Error fetching doctors:', error);
    res.status(500).json({ error: 'خطأ في جلب الأطباء' });
  }
});

// الموافقة على طبيب
app.put('/api/doctors/:doctorId/approve', async (req, res) => {
  try {
    const { doctorId } = req.params;
    await Doctor.findByIdAndUpdate(doctorId, { status: 'approved' });
    res.json({ message: 'تم الموافقة على الطبيب بنجاح' });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في الموافقة على الطبيب' });
  }
});

// رفض طبيب
app.put('/api/doctors/:doctorId/reject', async (req, res) => {
  try {
    const { doctorId } = req.params;
    await Doctor.findByIdAndUpdate(doctorId, { status: 'rejected' });
    res.json({ message: 'تم رفض الطبيب بنجاح' });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في رفض الطبيب' });
  }
});

// حذف طبيب
app.delete('/api/doctors/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    await Doctor.findByIdAndUpdate(doctorId, { active: false });
    res.json({ message: 'تم حذف الطبيب بنجاح' });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في حذف الطبيب' });
  }
});

// جلب جميع المواعيد
app.get('/api/appointments', async (req, res) => {
  try {
    const appointments = await Appointment.find()
      .populate('userId', 'first_name')
      .populate('doctorId', 'name')
      .sort({ createdAt: -1 });
    
    const formattedAppointments = appointments.map(appointment => ({
      id: appointment._id,
      user_name: appointment.userName || appointment.userId?.first_name || 'غير محدد',
      doctor_name: appointment.doctorName || appointment.doctorId?.name || 'غير محدد',
      date: appointment.date,
      time: appointment.time,
      status: appointment.status || 'pending',
      reason: appointment.reason || '',
      notes: appointment.notes || '',
      type: appointment.type || 'normal',
      serviceType: appointment.serviceType || 'doctor',
      serviceName: appointment.serviceName || '',
      price: appointment.price || 0,
      createdAt: appointment.createdAt
    }));
    
    res.json(formattedAppointments);
  } catch (error) {
    res.status(500).json({ error: 'خطأ في جلب المواعيد' });
  }
});

// تحديث حالة الموعد
app.put('/api/appointments/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const appointment = await Appointment.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ error: 'الموعد غير موجود' });
    }
    
    res.json({ message: 'تم تحديث حالة الموعد بنجاح', appointment });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في تحديث حالة الموعد' });
  }
});

// جلب التحليل والإحصائيات
app.get('/api/analytics', async (req, res) => {
  try {
    // أفضل الأطباء حسب عدد المواعيد
    const topDoctors = await Appointment.aggregate([
      {
        $group: {
          _id: '$doctorId',
          appointments: { $sum: 1 }
        }
      },
      {
        $lookup: {
          from: 'doctors',
          localField: '_id',
          foreignField: '_id',
          as: 'doctorInfo'
        }
      },
      {
        $unwind: '$doctorInfo'
      },
      {
        $project: {
          name: '$doctorInfo.name',
          specialty: '$doctorInfo.specialty',
          appointments: 1
        }
      },
      {
        $sort: { appointments: -1 }
      },
      {
        $limit: 5
      }
    ]);

    // أفضل التخصصات
    const topSpecialties = await Doctor.aggregate([
      {
        $group: {
          _id: '$specialty',
          count: { $sum: 1 }
        }
      },
      {
        $lookup: {
          from: 'appointments',
          localField: '_id',
          foreignField: 'doctorId',
          as: 'appointments'
        }
      },
      {
        $project: {
          specialty: '$_id',
          count: 1,
          appointments: { $size: '$appointments' }
        }
      },
      {
        $sort: { appointments: -1 }
      },
      {
        $limit: 5
      }
    ]);

    // الإحصائيات الشهرية
    const monthlyStats = await Appointment.aggregate([
      {
        $addFields: {
          month: { $month: '$createdAt' },
          year: { $year: '$createdAt' }
        }
      },
      {
        $group: {
          _id: { month: '$month', year: '$year' },
          appointments: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': -1, '_id.month': -1 }
      },
      {
        $limit: 6
      }
    ]);

    // نمو المستخدمين
    const userGrowth = await User.aggregate([
      {
        $addFields: {
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
        }
      },
      {
        $group: {
          _id: '$date',
          users: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      },
      {
        $limit: 10
      }
    ]);

    res.json({
      topDoctors,
      topSpecialties,
      monthlyStats,
      userGrowth
    });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في جلب التحليل' });
  }
});

// إضافة بيانات حقيقية للتحليل
app.post('/api/seed-analytics-data', async (req, res) => {
  try {
    // حذف البيانات الموجودة
    await User.deleteMany({});
    await Doctor.deleteMany({});
    await Appointment.deleteMany({});

    // إنشاء أطباء حقيقيين
    const doctors = await Doctor.insertMany([
      {
        name: 'د. أحمد محمد حسن',
        email: 'ahmed.hassan@tabibiq.com',
        phone: '07701234567',
        specialty: 'طب عام',
        experience: '15 سنة',
        status: 'approved',
        created_at: new Date('2024-01-15')
      },
      {
        name: 'د. سارة أحمد محمود',
        email: 'sara.ahmed@tabibiq.com',
        phone: '07701234568',
        specialty: 'أمراض القلب',
        experience: '12 سنة',
        status: 'approved',
        created_at: new Date('2024-01-20')
      },
      {
        name: 'د. علي محمود كريم',
        email: 'ali.mahmoud@tabibiq.com',
        phone: '07701234569',
        specialty: 'طب الأطفال',
        experience: '18 سنة',
        status: 'approved',
        created_at: new Date('2024-02-01')
      },
      {
        name: 'د. فاطمة حسن علي',
        email: 'fatima.hassan@tabibiq.com',
        phone: '07701234570',
        specialty: 'طب النساء والولادة',
        experience: '14 سنة',
        status: 'approved',
        created_at: new Date('2024-02-10')
      },
      {
        name: 'د. محمد عبدالله سعد',
        email: 'mohammed.abdullah@tabibiq.com',
        phone: '07701234571',
        specialty: 'طب عام',
        experience: '10 سنة',
        status: 'approved',
        created_at: new Date('2024-02-15')
      },
      {
        name: 'د. نورا سامي رضا',
        email: 'nora.sami@tabibiq.com',
        phone: '07701234572',
        specialty: 'طب العيون',
        experience: '16 سنة',
        status: 'approved',
        created_at: new Date('2024-03-01')
      },
      {
        name: 'د. حسين علي محمد',
        email: 'hussein.ali@tabibiq.com',
        phone: '07701234573',
        specialty: 'طب الأسنان',
        experience: '13 سنة',
        status: 'approved',
        created_at: new Date('2024-03-05')
      },
      {
        name: 'د. زينب أحمد حسن',
        email: 'zainab.ahmed@tabibiq.com',
        phone: '07701234574',
        specialty: 'طب عام',
        experience: '11 سنة',
        status: 'pending',
        created_at: new Date('2024-03-10')
      },
      {
        name: 'د. عمر محمد سعيد',
        email: 'omar.mohammed@tabibiq.com',
        phone: '07701234575',
        specialty: 'طب الأعصاب',
        experience: '20 سنة',
        status: 'pending',
        created_at: new Date('2024-03-12')
      },
      {
        name: 'د. ليلى عبدالرحمن',
        email: 'layla.abdulrahman@tabibiq.com',
        phone: '07701234576',
        specialty: 'طب الأمراض الجلدية',
        experience: '9 سنة',
        status: 'pending',
        created_at: new Date('2024-03-15')
      }
    ]);

    // إنشاء مستخدمين حقيقيين
    const users = await User.insertMany([
      {
        first_name: 'محمد',
        last_name: 'أحمد حسن',
        email: 'mohammed.ahmed@email.com',
        phone: '07701234577',
        password: 'password123',
        created_at: new Date('2024-01-01')
      },
      {
        first_name: 'فاطمة',
        last_name: 'علي محمود',
        email: 'fatima.ali@email.com',
        phone: '07701234578',
        password: 'password123',
        created_at: new Date('2024-01-05')
      },
      {
        first_name: 'أحمد',
        last_name: 'محمد سعد',
        email: 'ahmed.mohammed@email.com',
        phone: '07701234579',
        password: 'password123',
        created_at: new Date('2024-01-10')
      },
      {
        first_name: 'سارة',
        last_name: 'حسن علي',
        email: 'sara.hassan@email.com',
        phone: '07701234580',
        password: 'password123',
        created_at: new Date('2024-01-15')
      },
      {
        first_name: 'علي',
        last_name: 'أحمد كريم',
        email: 'ali.ahmed@email.com',
        phone: '07701234581',
        password: 'password123',
        created_at: new Date('2024-01-20')
      },
      {
        first_name: 'نورا',
        last_name: 'محمد سامي',
        email: 'nora.mohammed@email.com',
        phone: '07701234582',
        password: 'password123',
        created_at: new Date('2024-02-01')
      },
      {
        first_name: 'حسين',
        last_name: 'علي محمد',
        email: 'hussein.ali@email.com',
        phone: '07701234583',
        password: 'password123',
        created_at: new Date('2024-02-05')
      },
      {
        first_name: 'زينب',
        last_name: 'أحمد حسن',
        email: 'zainab.ahmed@email.com',
        phone: '07701234584',
        password: 'password123',
        created_at: new Date('2024-02-10')
      },
      {
        first_name: 'عمر',
        last_name: 'محمد سعيد',
        email: 'omar.mohammed@email.com',
        phone: '07701234585',
        password: 'password123',
        created_at: new Date('2024-02-15')
      },
      {
        first_name: 'ليلى',
        last_name: 'عبدالرحمن أحمد',
        email: 'layla.abdulrahman@email.com',
        phone: '07701234586',
        password: 'password123',
        created_at: new Date('2024-03-01')
      },
      {
        first_name: 'كريم',
        last_name: 'محمد علي',
        email: 'kareem.mohammed@email.com',
        phone: '07701234587',
        password: 'password123',
        created_at: new Date('2024-03-05')
      },
      {
        first_name: 'رنا',
        last_name: 'أحمد سعد',
        email: 'rana.ahmed@email.com',
        phone: '07701234588',
        password: 'password123',
        created_at: new Date('2024-03-10')
      }
    ]);

    // إنشاء مواعيد حقيقية
    const appointments = [];
    const appointmentDates = [
      '2024-01-20', '2024-01-25', '2024-02-01', '2024-02-05', '2024-02-10',
      '2024-02-15', '2024-02-20', '2024-02-25', '2024-03-01', '2024-03-05',
      '2024-03-10', '2024-03-15', '2024-03-20', '2024-03-25', '2024-03-30'
    ];

    // مواعيد لد. أحمد محمد حسن (طب عام) - 45 موعد
    for (let i = 0; i < 45; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[0]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[0].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-01-15')
      });
    }

    // مواعيد لد. سارة أحمد محمود (أمراض القلب) - 38 موعد
    for (let i = 0; i < 38; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[1]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[1].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-01-20')
      });
    }

    // مواعيد لد. علي محمود كريم (طب الأطفال) - 32 موعد
    for (let i = 0; i < 32; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[2]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[2].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-02-01')
      });
    }

    // مواعيد لد. فاطمة حسن علي (طب النساء) - 28 موعد
    for (let i = 0; i < 28; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[3]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[3].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-02-10')
      });
    }

    // مواعيد لد. محمد عبدالله سعد (طب عام) - 25 موعد
    for (let i = 0; i < 25; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[4]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[4].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-02-15')
      });
    }

    // مواعيد لد. نورا سامي رضا (طب العيون) - 22 موعد
    for (let i = 0; i < 22; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[5]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[5].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-03-01')
      });
    }

    // مواعيد لد. حسين علي محمد (طب الأسنان) - 18 موعد
    for (let i = 0; i < 18; i++) {
      appointments.push({
        userId: users[Math.floor(Math.random() * users.length)]._id,
        doctorId: doctors[6]._id,
        userName: users[Math.floor(Math.random() * users.length)].first_name + ' ' + users[Math.floor(Math.random() * users.length)].last_name,
        doctorName: doctors[6].name,
        date: appointmentDates[Math.floor(Math.random() * appointmentDates.length)],
        time: ['09:00', '10:00', '11:00', '14:00', '15:00', '16:00'][Math.floor(Math.random() * 6)],
        createdAt: new Date('2024-03-05')
      });
    }

    await Appointment.insertMany(appointments);

    res.json({ 
      message: 'تم إضافة البيانات الحقيقية بنجاح',
      stats: {
        doctors: doctors.length,
        users: users.length,
        appointments: appointments.length
      }
    });
  } catch (error) {
    console.error('خطأ في إضافة البيانات:', error);
    res.status(500).json({ error: 'خطأ في إضافة البيانات' });
  }
});

// ==================== APIs الأطباء المميزين ====================

// إضافة طبيب إلى المميزين (API جديد)
app.put('/doctors/:doctorId/feature', async (req, res) => {
  try {
    console.log('⭐ محاولة إضافة طبيب للمميزين:', req.params.doctorId);
    
    const doctor = await Doctor.findByIdAndUpdate(
      req.params.doctorId,
      { is_featured: true },
      { new: true }
    );
    
    if (!doctor) {
      console.log('❌ الطبيب غير موجود:', req.params.doctorId);
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    console.log('✅ تم إضافة الطبيب إلى المميزين:', doctor.name, 'is_featured:', doctor.is_featured);
    res.json({ message: 'تم إضافة الطبيب إلى المميزين بنجاح', doctor });
  } catch (error) {
    console.error('❌ خطأ في إضافة الطبيب إلى المميزين:', error);
    res.status(500).json({ error: 'خطأ في إضافة الطبيب إلى المميزين' });
  }
});

// إزالة طبيب من المميزين (API جديد)
app.put('/doctors/:doctorId/unfeature', async (req, res) => {
  try {
    console.log('❌ محاولة إزالة طبيب من المميزين:', req.params.doctorId);
    
    const doctor = await Doctor.findByIdAndUpdate(
      req.params.doctorId,
      { is_featured: false },
      { new: true }
    );
    
    if (!doctor) {
      console.log('❌ الطبيب غير موجود:', req.params.doctorId);
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    console.log('✅ تم إزالة الطبيب من المميزين:', doctor.name, 'is_featured:', doctor.is_featured);
    res.json({ message: 'تم إزالة الطبيب من المميزين بنجاح', doctor });
  } catch (error) {
    console.error('❌ خطأ في إزالة الطبيب من المميزين:', error);
    res.status(500).json({ error: 'خطأ في إزالة الطبيب من المميزين' });
  }
});

// APIs اختبار للأطباء المميزين
app.put('/doctors/test-feature', async (req, res) => {
  try {
    console.log('🧪 اختبار API إضافة مميز...');
    res.json({ message: 'API إضافة مميز يعمل بشكل صحيح', test: true });
  } catch (error) {
    console.error('❌ خطأ في اختبار API إضافة مميز:', error);
    res.status(500).json({ error: 'خطأ في اختبار API' });
  }
});

app.put('/doctors/test-unfeature', async (req, res) => {
  try {
    console.log('🧪 اختبار API إزالة مميز...');
    res.json({ message: 'API إزالة مميز يعمل بشكل صحيح', test: true });
  } catch (error) {
    console.error('❌ خطأ في اختبار API إزالة مميز:', error);
    res.status(500).json({ error: 'خطأ في اختبار API' });
  }
});

// إضافة طبيب إلى المميزين (API قديم - للتوافق)
app.put('/api/doctors/:doctorId/feature', async (req, res) => {
  try {
    console.log('🔍 محاولة إضافة طبيب للمميزين:', req.params.doctorId);
    
    const doctor = await Doctor.findByIdAndUpdate(
      req.params.doctorId,
      { is_featured: true },
      { new: true }
    );
    
    if (!doctor) {
      console.log('❌ الطبيب غير موجود:', req.params.doctorId);
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    console.log('✅ تم إضافة الطبيب إلى المميزين:', doctor.name, 'is_featured:', doctor.is_featured);
    res.json({ message: 'تم إضافة الطبيب إلى المميزين بنجاح', doctor });
  } catch (error) {
    console.error('❌ خطأ في إضافة الطبيب إلى المميزين:', error);
    res.status(500).json({ error: 'خطأ في إضافة الطبيب إلى المميزين' });
  }
});

// إزالة طبيب من المميزين (API قديم - للتوافق)
app.put('/api/doctors/:doctorId/unfeature', async (req, res) => {
  try {
    console.log('🔍 محاولة إزالة طبيب من المميزين:', req.params.doctorId);
    
    const doctor = await Doctor.findByIdAndUpdate(
      req.params.doctorId,
      { is_featured: false },
      { new: true }
    );
    
    if (!doctor) {
      console.log('❌ الطبيب غير موجود:', req.params.doctorId);
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    console.log('✅ تم إزالة الطبيب من المميزين:', doctor.name, 'is_featured:', doctor.is_featured);
    res.json({ message: 'تم إزالة الطبيب من المميزين بنجاح', doctor });
  } catch (error) {
    console.error('❌ خطأ في إزالة الطبيب من المميزين:', error);
    res.status(500).json({ error: 'خطأ في إزالة الطبيب من المميزين' });
  }
});

// جلب الأطباء المميزين
app.get('/api/doctors/featured', async (req, res) => {
  try {
    console.log('🔍 جلب الأطباء المميزين...');
    
    const featuredDoctors = await Doctor.find({ 
      is_featured: true, 
      status: 'approved' 
    }).sort({ created_at: -1 });
    
    console.log('📊 عدد الأطباء المميزين الموجودين:', featuredDoctors.length);
    
    const formattedDoctors = featuredDoctors.map(doctor => ({
      id: doctor._id,
      name: doctor.name,
      email: doctor.email,
      phone: doctor.phone,
      specialty: doctor.specialty,
      experience: doctor.experienceYears,
      status: doctor.status,
      is_featured: doctor.is_featured,
      created_at: doctor.created_at
    }));
    
    console.log('✅ تم جلب الأطباء المميزين بنجاح');
    res.json(formattedDoctors);
  } catch (error) {
    console.error('❌ خطأ في جلب الأطباء المميزين:', error);
    res.status(500).json({ error: 'خطأ في جلب الأطباء المميزين' });
  }
});

// ==================== APIs إدارة الأدمن ====================

// جلب قائمة الأدمن
app.get('/admins', async (req, res) => {
  try {
    const admins = await Admin.find({}, { password: 0, __v: 0 })
      .sort({ createdAt: -1 });
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب قائمة الأدمن' });
  }
});

// إنشاء أدمن جديد
app.post('/admins', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // تحقق من وجود الإيميل
    const existingAdmin = await Admin.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (existingAdmin) return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقًا' });
    
    const hashed = await bcrypt.hash(password, 10);
    const admin = new Admin({ email, password: hashed, name });
    await admin.save();
    res.json({ message: 'تم إنشاء حساب الأدمن بنجاح!' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء حساب الأدمن' });
  }
});

// تحديث بيانات الأدمن
app.put('/admins/:id', async (req, res) => {
  try {
    const { email, name, password } = req.body;
    const updateData = { email, name };
    
    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }
    
    const admin = await Admin.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!admin) return res.status(404).json({ error: 'الأدمن غير موجود' });
    
    res.json({ message: 'تم تحديث بيانات الأدمن بنجاح', admin: { ...admin.toObject(), password: undefined } });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث بيانات الأدمن' });
  }
});

// حذف أدمن
app.delete('/admins/:id', async (req, res) => {
  try {
    const admin = await Admin.findByIdAndDelete(req.params.id);
    if (!admin) return res.status(404).json({ error: 'الأدمن غير موجود' });
    
    res.json({ message: 'تم حذف الأدمن بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حذف الأدمن' });
  }
});

// تعريف سكيم MedicineReminder إذا لم يكن معرف مسبقاً
const medicineReminderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  medicineName: String,
  dosage: String,
  times: [String], // ["08:00", "20:00"]
  startDate: String, // "2024-06-01"
  endDate: String,   // "2024-06-10"
  createdAt: { type: Date, default: Date.now }
});
const MedicineReminder = mongoose.models.MedicineReminder || mongoose.model('MedicineReminder', medicineReminderSchema);

// إضافة تذكير دواء جديد
app.post('/medicine-reminders', async (req, res) => {
  try {
    const { userId, medicineName, dosage, times, startDate, endDate } = req.body;
    const reminder = new MedicineReminder({
      userId,
      medicineName,
      dosage,
      times,      // مصفوفة أوقات ["08:00", "20:00"]
      startDate,  // "2024-06-01"
      endDate     // "2024-06-10"
    });
    await reminder.save();
    res.json({ success: true, reminder });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// جلب تذكيرات الدواء لمستخدم
app.get('/medicine-reminders/:userId', async (req, res) => {
  try {
    const reminders = await MedicineReminder.find({ userId: req.params.userId });
    res.json({ success: true, reminders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

const PORT = process.env.PORT || 5000;

// Improved server startup with error handling
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 Server started successfully!');
  console.log(`🌐 Server running on port ${PORT}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`⏰ Started at: ${new Date().toISOString()}`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('❌ Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error('🔍 Port is already in use. Please try a different port.');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    mongoose.connection.close(() => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    mongoose.connection.close().then(() => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    }).catch(err => {
      console.log('❌ Error closing MongoDB connection:', err.message);
      process.exit(0);
    });
  });
});

// إضافة موعد خاص (special appointment)
app.post('/add-special-appointment', async (req, res) => {
  try {
    console.log('بيانات الطلب:', req.body); // طباعة بيانات الطلب
    const {
      userId,
      doctorId,
      userName,
      doctorName,
      date,
      time,
      reason,
      notes,
      priority,
      duration,
      status
    } = req.body;

    if (!doctorId || !date || !time) {
      return res.status(400).json({ success: false, error: 'البيانات الأساسية ناقصة' });
    }

    // تعديل: البحث عن المستخدم حسب رقم الهاتف
    let foundUser = null;
    let normPhone = null;
    if (req.body.patientPhone) {
      normPhone = normalizePhone(req.body.patientPhone);
      console.log('رقم الهاتف بعد التوحيد:', normPhone); // طباعة الرقم بعد التوحيد
      foundUser = await User.findOne({ phone: normPhone });
      console.log('نتيجة البحث عن المستخدم:', foundUser); // طباعة نتيجة البحث
    }

    const appointment = new Appointment({
      userId: foundUser ? foundUser._id : (userId || null),
      doctorId,
      userName: userName || '',
      doctorName: doctorName || '',
      date,
      time,
      reason: reason || 'موعد خاص',
      notes: notes || '',
      priority: priority || 'normal',
      duration: duration || '30',
      status: status || 'pending',
      type: 'special_appointment',
      patientPhone: req.body.patientPhone || '' // <-- أضفت هذا السطر
    });

    await appointment.save();

    // إرسال إشعار للمستخدم إذا كان رقم الهاتف مرتبط بحساب
    try {
      if (foundUser) {
        const notification = new Notification({
          userId: foundUser._id,
          type: 'special_appointment',
          message: `تم حجز موعد خاص لك مع الطبيب ${doctorName} بتاريخ ${date} الساعة ${time}`,
          read: false
        });
        await notification.save();
      }
      // أرسل إشعار أيضًا عبر دالة الإشعار المركزية
      const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
      const baseUrl = process.env.API_URL || `${req.protocol}://${req.get('host')}`;
      await fetch(`${baseUrl}/send-special-appointment-notification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          patientPhone: req.body.patientPhone,
          patientName: userName,
          doctorId,
          doctorName,
          newDate: date,
          newTime: time,
          reason,
          notes
        })
      });
    } catch (e) { /* تجاهل الخطأ حتى لا يؤثر على إضافة الموعد */ }

    res.json({ success: true, appointment });

  } catch (err) {
    res.status(500).json({
      success: false,
      error: 'حدث خطأ أثناء إضافة الموعد الخاص',
      details: err.message
    });
  }
});

// جلب مواعيد اليوم الخاصة للطبيب
app.get('/doctor-today-special-appointments/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const today = new Date().toISOString().slice(0, 10);
    const appointments = await Appointment.find({
      doctorId,
      type: 'special_appointment',
      date: today
    }).sort({ time: 1 })
      .populate('userId', 'first_name phone');
    res.json(appointments);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب مواعيد اليوم الخاصة للطبيب' });
  }
});

// توحيد كل أرقام المستخدمين في قاعدة البيانات
app.post('/normalize-all-phones', async (req, res) => {
  try {
    const users = await User.find({});
    let updated = 0;
    for (const user of users) {
      const newPhone = normalizePhone(user.phone);
      if (user.phone !== newPhone) {
        user.phone = newPhone;
        await user.save();
        updated++;
      }
    }
    res.json({ success: true, updated, message: `تم توحيد ${updated} رقم هاتف.` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Endpoint لرفع الصورة الشخصية
app.post('/upload-profile-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'لم يتم رفع أي صورة' });
    }

    // التحقق من نوع الملف
    if (!req.file.mimetype.startsWith('image/')) {
      // حذف الملف المحلي
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'يجب أن يكون الملف صورة' });
    }

    // التحقق من حجم الملف (أقل من 5MB)
    if (req.file.size > 5 * 1024 * 1024) {
      // حذف الملف المحلي
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'حجم الصورة يجب أن يكون أقل من 5 ميجابايت' });
    }

    let imageUrl;
    let uploadSuccess = false;
    
    // محاولة رفع الصورة إلى Cloudinary أولاً
    if (process.env.CLOUDINARY_URL) {
      try {
        console.log('🔄 Attempting to upload to Cloudinary...');
        const result = await cloudinary.uploader.upload(req.file.path, {
          folder: 'tabibiq-profiles',
          transformation: [
            { width: 400, height: 400, crop: 'fill', gravity: 'face' },
            { quality: 'auto', fetch_format: 'auto' }
          ],
          resource_type: 'image'
        });
        imageUrl = result.secure_url;
        uploadSuccess = true;
        console.log('✅ Image uploaded to Cloudinary successfully:', imageUrl);
        
        // حذف الملف المحلي بعد رفعه إلى Cloudinary
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
          console.log('🗑️ Local file deleted after Cloudinary upload');
        }
      } catch (cloudinaryError) {
        console.error('❌ Cloudinary upload failed:', cloudinaryError);
        // إذا فشل Cloudinary، استخدم التخزين المحلي
        const baseUrl = process.env.API_URL || `${req.protocol}://${req.get('host')}`;
        imageUrl = `${baseUrl}/uploads/${req.file.filename}`;
        console.log('📁 Using local storage as fallback:', imageUrl);
      }
    } else {
      // استخدام التخزين المحلي إذا لم يتم إعداد Cloudinary
      const baseUrl = process.env.API_URL || `${req.protocol}://${req.get('host')}`;
      imageUrl = `${baseUrl}/uploads/${req.file.filename}`;
      console.log('📁 Using local storage:', imageUrl);
    }
    
    res.json({ 
      success: true, 
      imageUrl,
      uploadSuccess,
      message: 'تم رفع الصورة بنجاح' 
    });
  } catch (err) {
    console.error('❌ Error in image upload:', err);
    
    // حذف الملف المحلي في حالة الخطأ
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('🗑️ Local file deleted due to error');
      } catch (deleteError) {
        console.error('❌ Error deleting local file:', deleteError);
      }
    }
    
    res.status(500).json({ error: 'حدث خطأ أثناء رفع الصورة' });
  }
});

// Endpoint لخدمة الصور المرفوعة
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// إضافة CORS للصور
app.use('/uploads', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Cache-Control', 'public, max-age=31536000'); // كاش لمدة سنة
  res.header('Expires', new Date(Date.now() + 31536000000).toUTCString());
  
  // معالجة preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// اختبار Cloudinary
app.get('/test-cloudinary', async (req, res) => {
  try {
    console.log('🔍 Testing Cloudinary configuration...');
    console.log('CLOUDINARY_URL:', process.env.CLOUDINARY_URL ? 'Set' : 'Not set');
    console.log('CLOUDINARY_CLOUD_NAME:', process.env.CLOUDINARY_CLOUD_NAME);
    console.log('CLOUDINARY_API_KEY:', process.env.CLOUDINARY_API_KEY ? 'Set' : 'Not set');
    
    if (!process.env.CLOUDINARY_URL) {
      return res.json({ 
        status: 'warning', 
        message: 'Cloudinary غير مُعد',
        cloudinaryConfigured: false,
        env: {
          CLOUDINARY_URL: 'Not set',
          CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME,
          CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY ? 'Set' : 'Not set'
        }
      });
    }

    // اختبار الاتصال بـ Cloudinary
    console.log('🔄 Attempting to ping Cloudinary...');
    const result = await cloudinary.api.ping();
    console.log('✅ Cloudinary ping successful:', result);
    
    res.json({ 
      status: 'success', 
      message: 'Cloudinary يعمل بشكل صحيح',
      cloudinaryConfigured: true,
      ping: result,
      env: {
        CLOUDINARY_URL: 'Set',
        CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME,
        CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY ? 'Set' : 'Not set'
      }
    });
  } catch (error) {
    console.error('❌ Cloudinary test failed:', error);
    res.json({ 
      status: 'error', 
      message: 'خطأ في الاتصال بـ Cloudinary',
      cloudinaryConfigured: false,
      error: error.message,
      env: {
        CLOUDINARY_URL: process.env.CLOUDINARY_URL ? 'Set' : 'Not set',
        CLOUDINARY_CLOUD_NAME: process.env.CLOUDINARY_CLOUD_NAME,
        CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY ? 'Set' : 'Not set'
      }
    });
  }
});

// اختبار بديل للصور
app.get('/test-image-upload', (req, res) => {
  res.json({
    status: 'info',
    message: 'نظام رفع الصور جاهز للاختبار',
    endpoints: {
      upload: 'POST /upload-profile-image',
      test: 'GET /test-cloudinary',
      health: 'GET /api/health'
    },
    config: {
      uploadDir: uploadDir,
      maxFileSize: '5MB',
      allowedTypes: 'image/*',
      cloudinaryConfigured: !!process.env.CLOUDINARY_URL
    }
  });
});

// جلب صورة الدكتور
app.get('/doctor-image/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const doctor = await Doctor.findById(doctorId).select('image profileImage');
    
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    // إرجاع الصورة المتاحة (image أو profileImage)
    let imageUrl = doctor.image || doctor.profileImage;
    
    if (!imageUrl) {
      return res.status(404).json({ error: 'لا توجد صورة للطبيب' });
    }
    
    // إذا كانت الصورة محلية وCloudinary مُعد، حاول تحويلها تلقائياً
    if (imageUrl.startsWith('/uploads/') && process.env.CLOUDINARY_URL) {
      try {
        const localPath = path.join(__dirname, imageUrl);
        if (fs.existsSync(localPath)) {
          console.log(`🔄 تحويل تلقائي للصورة المحلية: ${imageUrl}`);
          
          const result = await cloudinary.uploader.upload(localPath, {
            folder: 'tabibiq-profiles',
            transformation: [
              { width: 400, height: 400, crop: 'fill', gravity: 'face' },
              { quality: 'auto', fetch_format: 'auto' }
            ]
          });
          
          // تحديث قاعدة البيانات
          if (doctor.image === imageUrl) {
            doctor.image = result.secure_url;
          } else if (doctor.profileImage === imageUrl) {
            doctor.profileImage = result.secure_url;
          }
          await doctor.save();
          
          imageUrl = result.secure_url;
          console.log(`✅ تم تحويل الصورة تلقائياً إلى Cloudinary: ${imageUrl}`);
        }
      } catch (error) {
        console.error(`❌ خطأ في التحويل التلقائي للصورة: ${error.message}`);
        // إذا فشل التحويل، استخدم الرابط المحلي
        imageUrl = `${req.protocol}://${req.get('host')}${imageUrl}`;
      }
    } else if (imageUrl.startsWith('/uploads/')) {
      // إذا كانت محلية وCloudinary غير مُعد
      imageUrl = `${req.protocol}://${req.get('host')}${imageUrl}`;
    }
    
    res.json({ 
      imageUrl,
      hasImage: true 
    });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب صورة الطبيب' });
  }
});

// تحويل الصور المحلية إلى Cloudinary تلقائياً
app.post('/migrate-local-images', async (req, res) => {
  try {
    if (!process.env.CLOUDINARY_URL) {
      return res.status(400).json({ error: 'Cloudinary غير مُعد' });
    }

    console.log('🔄 بدء تحويل الصور المحلية إلى Cloudinary...');
    
    // جلب جميع الأطباء والمستخدمين الذين لديهم صور محلية
    const doctors = await Doctor.find({
      $or: [
        { image: { $regex: '^/uploads/', $options: 'i' } },
        { profileImage: { $regex: '^/uploads/', $options: 'i' } }
      ]
    });
    
    const users = await User.find({
      $or: [
        { image: { $regex: '^/uploads/', $options: 'i' } },
        { profileImage: { $regex: '^/uploads/', $options: 'i' } }
      ]
    });

    const results = {
      doctors: { total: doctors.length, migrated: 0, failed: 0 },
      users: { total: users.length, migrated: 0, failed: 0 },
      errors: []
    };

    // تحويل صور الأطباء
    for (const doctor of doctors) {
      try {
        let updated = false;
        
        // تحويل حقل image
        if (doctor.image && doctor.image.startsWith('/uploads/')) {
          const localPath = path.join(__dirname, doctor.image);
          if (fs.existsSync(localPath)) {
            const result = await cloudinary.uploader.upload(localPath, {
              folder: 'tabibiq-profiles',
              transformation: [
                { width: 400, height: 400, crop: 'fill', gravity: 'face' },
                { quality: 'auto', fetch_format: 'auto' }
              ]
            });
            doctor.image = result.secure_url;
            updated = true;
            console.log(`✅ تم تحويل صورة الطبيب ${doctor.name} (image): ${result.secure_url}`);
          }
        }
        
        // تحويل حقل profileImage
        if (doctor.profileImage && doctor.profileImage.startsWith('/uploads/')) {
          const localPath = path.join(__dirname, doctor.profileImage);
          if (fs.existsSync(localPath)) {
            const result = await cloudinary.uploader.upload(localPath, {
              folder: 'tabibiq-profiles',
              transformation: [
                { width: 400, height: 400, crop: 'fill', gravity: 'face' },
                { quality: 'auto', fetch_format: 'auto' }
              ]
            });
            doctor.profileImage = result.secure_url;
            updated = true;
            console.log(`✅ تم تحويل صورة الطبيب ${doctor.name} (profileImage): ${result.secure_url}`);
          }
        }
        
        if (updated) {
          await doctor.save();
          results.doctors.migrated++;
        }
      } catch (error) {
        console.error(`❌ خطأ في تحويل صورة الطبيب ${doctor.name}:`, error);
        results.doctors.failed++;
        results.errors.push(`Doctor ${doctor.name}: ${error.message}`);
      }
    }

    // تحويل صور المستخدمين
    for (const user of users) {
      try {
        let updated = false;
        
        // تحويل حقل image
        if (user.image && user.image.startsWith('/uploads/')) {
          const localPath = path.join(__dirname, user.image);
          if (fs.existsSync(localPath)) {
            const result = await cloudinary.uploader.upload(localPath, {
              folder: 'tabibiq-profiles',
              transformation: [
                { width: 400, height: 400, crop: 'fill', gravity: 'face' },
                { quality: 'auto', fetch_format: 'auto' }
              ]
            });
            user.image = result.secure_url;
            updated = true;
            console.log(`✅ تم تحويل صورة المستخدم ${user.first_name} (image): ${result.secure_url}`);
          }
        }
        
        // تحويل حقل profileImage
        if (user.profileImage && user.profileImage.startsWith('/uploads/')) {
          const localPath = path.join(__dirname, user.profileImage);
          if (fs.existsSync(localPath)) {
            const result = await cloudinary.uploader.upload(localPath, {
              folder: 'tabibiq-profiles',
              transformation: [
                { width: 400, height: 400, crop: 'fill', gravity: 'face' },
                { quality: 'auto', fetch_format: 'auto' }
              ]
            });
            user.profileImage = result.secure_url;
            updated = true;
            console.log(`✅ تم تحويل صورة المستخدم ${user.first_name} (profileImage): ${result.secure_url}`);
          }
        }
        
        if (updated) {
          await user.save();
          results.users.migrated++;
        }
      } catch (error) {
        console.error(`❌ خطأ في تحويل صورة المستخدم ${user.first_name}:`, error);
        results.users.failed++;
        results.errors.push(`User ${user.first_name}: ${error.message}`);
      }
    }

    console.log('✅ انتهى تحويل الصور المحلية إلى Cloudinary');
    res.json({
      success: true,
      message: 'تم تحويل الصور المحلية إلى Cloudinary بنجاح',
      results
    });
  } catch (err) {
    console.error('❌ خطأ في تحويل الصور المحلية:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تحويل الصور المحلية' });
  }
});

// تحويل صورة واحدة محددة إلى Cloudinary
app.post('/migrate-single-image', async (req, res) => {
  try {
    const { imagePath, userId, userType } = req.body; // userType: 'doctor' or 'user'
    
    if (!process.env.CLOUDINARY_URL) {
      return res.status(400).json({ error: 'Cloudinary غير مُعد' });
    }

    if (!imagePath || !imagePath.startsWith('/uploads/')) {
      return res.status(400).json({ error: 'مسار الصورة غير صحيح' });
    }

    console.log(`🔄 بدء تحويل الصورة: ${imagePath}`);
    
    const localPath = path.join(__dirname, imagePath);
    if (!fs.existsSync(localPath)) {
      console.log(`❌ الملف غير موجود على الخادم: ${localPath}`);
      
      // إذا كان الملف غير موجود، حاول البحث عن نسخة بديلة
      const fileName = path.basename(imagePath);
      const uploadsDir = path.join(__dirname, 'uploads');
      
      if (fs.existsSync(uploadsDir)) {
        const files = fs.readdirSync(uploadsDir);
        const similarFile = files.find(file => file.includes(fileName.split('-')[0]));
        
        if (similarFile) {
          console.log(`🔄 تم العثور على ملف مشابه: ${similarFile}`);
          const alternativePath = path.join(uploadsDir, similarFile);
          const alternativeImagePath = `/uploads/${similarFile}`;
          
          // تحديث مسار الصورة في قاعدة البيانات
          if (userType === 'doctor') {
            const doctor = await Doctor.findById(userId);
            if (doctor) {
              if (doctor.image === imagePath) {
                doctor.image = alternativeImagePath;
              } else if (doctor.profileImage === imagePath) {
                doctor.profileImage = alternativeImagePath;
              }
              await doctor.save();
            }
          } else if (userType === 'user') {
            const user = await User.findById(userId);
            if (user) {
              if (user.image === imagePath) {
                user.image = alternativeImagePath;
              } else if (user.profileImage === imagePath) {
                user.profileImage = alternativeImagePath;
              }
              await user.save();
            }
          }
          
          // استخدام الملف البديل
          const result = await cloudinary.uploader.upload(alternativePath, {
            folder: 'tabibiq-profiles',
            transformation: [
              { width: 400, height: 400, crop: 'fill', gravity: 'face' },
              { quality: 'auto', fetch_format: 'auto' }
            ]
          });
          
          const cloudinaryUrl = result.secure_url;
          console.log(`✅ تم تحويل الملف البديل إلى Cloudinary: ${cloudinaryUrl}`);
          
          res.json({
            success: true,
            message: 'تم تحويل الصورة البديلة إلى Cloudinary بنجاح',
            cloudinaryUrl,
            updatedRecord: {
              id: userId,
              originalPath: imagePath,
              alternativePath: alternativeImagePath,
              cloudinaryUrl: cloudinaryUrl
            }
          });
          return;
        }
      }
      
      return res.status(404).json({ error: 'الملف غير موجود على الخادم ولا توجد نسخة بديلة' });
    }

    // رفع الصورة إلى Cloudinary
    const result = await cloudinary.uploader.upload(localPath, {
      folder: 'tabibiq-profiles',
      transformation: [
        { width: 400, height: 400, crop: 'fill', gravity: 'face' },
        { quality: 'auto', fetch_format: 'auto' }
      ]
    });

    const cloudinaryUrl = result.secure_url;
    console.log(`✅ تم رفع الصورة إلى Cloudinary: ${cloudinaryUrl}`);

    // تحديث قاعدة البيانات
    let updatedRecord = null;
    if (userType === 'doctor') {
      const doctor = await Doctor.findById(userId);
      if (doctor) {
        if (doctor.image === imagePath) {
          doctor.image = cloudinaryUrl;
        } else if (doctor.profileImage === imagePath) {
          doctor.profileImage = cloudinaryUrl;
        }
        await doctor.save();
        updatedRecord = doctor;
      }
    } else if (userType === 'user') {
      const user = await User.findById(userId);
      if (user) {
        if (user.image === imagePath) {
          user.image = cloudinaryUrl;
        } else if (user.profileImage === imagePath) {
          user.profileImage = cloudinaryUrl;
        }
        await user.save();
        updatedRecord = user;
      }
    }

    res.json({
      success: true,
      message: 'تم تحويل الصورة إلى Cloudinary بنجاح',
      cloudinaryUrl,
      updatedRecord: updatedRecord ? {
        id: updatedRecord._id,
        name: updatedRecord.name || updatedRecord.first_name
      } : null
    });
  } catch (err) {
    console.error('❌ خطأ في تحويل الصورة المفردة:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تحويل الصورة' });
  }
});

// جلب صورة المستخدم
app.get('/user-image/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId).select('image profileImage');
    
    if (!user) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }
    
    // إرجاع الصورة المتاحة (image أو profileImage)
    let imageUrl = user.image || user.profileImage;
    
    if (!imageUrl) {
      return res.status(404).json({ error: 'لا توجد صورة للمستخدم' });
    }
    
    // إذا كانت الصورة محلية وCloudinary مُعد، حاول تحويلها تلقائياً
    if (imageUrl.startsWith('/uploads/') && process.env.CLOUDINARY_URL) {
      try {
        const localPath = path.join(__dirname, imageUrl);
        if (fs.existsSync(localPath)) {
          console.log(`🔄 تحويل تلقائي للصورة المحلية: ${imageUrl}`);
          
          const result = await cloudinary.uploader.upload(localPath, {
            folder: 'tabibiq-profiles',
            transformation: [
              { width: 400, height: 400, crop: 'fill', gravity: 'face' },
              { quality: 'auto', fetch_format: 'auto' }
            ]
          });
          
          // تحديث قاعدة البيانات
          if (user.image === imageUrl) {
            user.image = result.secure_url;
          } else if (user.profileImage === imageUrl) {
            user.profileImage = result.secure_url;
          }
          await user.save();
          
          imageUrl = result.secure_url;
          console.log(`✅ تم تحويل الصورة تلقائياً إلى Cloudinary: ${imageUrl}`);
        }
      } catch (error) {
        console.error(`❌ خطأ في التحويل التلقائي للصورة: ${error.message}`);
        // إذا فشل التحويل، استخدم الرابط المحلي
        imageUrl = `${req.protocol}://${req.get('host')}${imageUrl}`;
      }
    } else if (imageUrl.startsWith('/uploads/')) {
      // إذا كانت محلية وCloudinary غير مُعد
      imageUrl = `${req.protocol}://${req.get('host')}${imageUrl}`;
    }
    
    res.json({ 
      imageUrl,
      hasImage: true 
    });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في جلب صورة المستخدم' });
  }
});

// Middleware لتسجيل الطلبات
app.use((req, res, next) => {
  console.log('📥 طلب جديد:', req.method, req.url);
  next();
});

// endpoint للتحقق من حالة الخادم
app.get('/server-status', (req, res) => {
  res.json({
    status: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    cloudinary: {
      configured: !!process.env.CLOUDINARY_URL,
      cloudName: process.env.CLOUDINARY_CLOUD_NAME,
      apiKey: process.env.CLOUDINARY_API_KEY ? 'Set' : 'Not set'
    },
    upload: {
      directory: uploadDir,
      exists: fs.existsSync(uploadDir)
    },
    endpoints: {
      health: '/api/health',
      testCloudinary: '/test-cloudinary',
      testImageUpload: '/test-image-upload',
      uploadProfileImage: '/upload-profile-image'
    }
  });
});

// Endpoint لتعطيل أو تفعيل حساب مستخدم أو دكتور
app.post('/admin/toggle-account/:type/:id', async (req, res) => {
  try {
    const { type, id } = req.params;
    const { disabled } = req.body;
    let model;
    if (type === 'user') model = User;
    else if (type === 'doctor') model = Doctor;
    else return res.status(400).json({ error: 'نوع الحساب غير مدعوم' });

    // حاول تحويل id إلى ObjectId إذا كان طوله 24
    let queryId = id;
    if (id.length === 24) {
      try { queryId = mongoose.Types.ObjectId(id); } catch(e) {}
    }

    const updated = await model.findByIdAndUpdate(queryId, { disabled: !!disabled }, { new: true });
    if (!updated) return res.status(404).json({ error: 'الحساب غير موجود' });
    res.json({ message: `تم تحديث حالة الحساب (${type}) بنجاح`, account: updated });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث حالة الحساب', details: err.message });
  }
});

// تحديث أوقات الدوام للطبيب
app.put('/doctor/:id/work-times', async (req, res) => {
  try {
    const { id } = req.params;
    const { workTimes } = req.body;

    if (!workTimes || !Array.isArray(workTimes)) {
      return res.status(400).json({ error: 'بيانات أوقات الدوام غير صحيحة' });
    }

    const doctor = await Doctor.findByIdAndUpdate(
      id,
      { workTimes },
      { new: true }
    );

    if (!doctor) {
      return res.status(404).json({ error: 'لم يتم العثور على الطبيب' });
    }

    res.json({ 
      message: 'تم تحديث أوقات الدوام بنجاح',
      workTimes: doctor.workTimes 
    });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث أوقات الدوام' });
  }
});

// تحديث مدة الموعد الافتراضية للطبيب
app.put('/doctor/:id/appointment-duration', async (req, res) => {
  try {
    const { id } = req.params;
    const { appointmentDuration } = req.body;

    if (!appointmentDuration || typeof appointmentDuration !== 'number') {
      return res.status(400).json({ error: 'مدة الموعد غير صحيحة' });
    }

    // التحقق من أن المدة ضمن القيم المسموحة
    const allowedDurations = [5, 10, 15, 20, 30, 45, 60];
    if (!allowedDurations.includes(appointmentDuration)) {
      return res.status(400).json({ error: 'مدة الموعد غير مسموحة' });
    }

    const doctor = await Doctor.findByIdAndUpdate(
      id,
      { appointmentDuration },
      { new: true }
    );

    if (!doctor) {
      return res.status(404).json({ error: 'لم يتم العثور على الطبيب' });
    }

    res.json({ 
      message: 'تم تحديث مدة الموعد الافتراضية بنجاح',
      appointmentDuration: doctor.appointmentDuration 
    });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث مدة الموعد' });
  }
});

// تنظيف المواعيد المكررة
app.post('/clean-duplicate-appointments', async (req, res) => {
  try {
    console.log('🔧 بدء تنظيف المواعيد المكررة...');
    
    // جلب جميع المواعيد
    const allAppointments = await Appointment.find({}).sort({ createdAt: 1 });
    
    // تجميع المواعيد المكررة
    const duplicatesMap = new Map();
    const duplicatesToDelete = [];
    
    allAppointments.forEach(appointment => {
      const userName = appointment.userName || (appointment.userId ? appointment.userId.first_name : '') || '';
      const key = `${appointment.doctorId}_${appointment.date}_${appointment.time}_${userName}_${appointment.type || 'normal'}`;
      
      if (duplicatesMap.has(key)) {
        // هذا موعد مكرر، أضفه لقائمة الحذف
        duplicatesToDelete.push(appointment._id);
      } else {
        duplicatesMap.set(key, appointment._id);
      }
    });
    
    console.log(`🔧 تم العثور على ${duplicatesToDelete.length} موعد مكرر`);
    
    // حذف المواعيد المكررة
    if (duplicatesToDelete.length > 0) {
      const deleteResult = await Appointment.deleteMany({ _id: { $in: duplicatesToDelete } });
      console.log(`🔧 تم حذف ${deleteResult.deletedCount} موعد مكرر`);
    }
    
    res.json({ 
      success: true, 
      duplicatesDeleted: duplicatesToDelete.length,
      message: `تم تنظيف ${duplicatesToDelete.length} موعد مكرر بنجاح`
    });
    
  } catch (err) {
    console.error('❌ خطأ في تنظيف المواعيد المكررة:', err);
    res.status(500).json({ 
      success: false, 
      error: 'حدث خطأ أثناء تنظيف المواعيد المكررة',
      details: err.message 
    });
  }
});

// إضافة موعد خاص (special appointment)