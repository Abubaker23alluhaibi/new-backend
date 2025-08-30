// تحميل متغيرات البيئة - Railway يستخدم متغيرات البيئة مباشرة
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config({ path: 'env.local' });
}

// طباعة متغيرات البيئة للتشخيص
console.log('🔧 Environment Variables:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('PORT:', process.env.PORT);
console.log('MONGO_URI:', process.env.MONGO_URI ? 'Set' : 'Not set');
console.log('JWT_SECRET:', process.env.JWT_SECRET ? 'Set' : 'Not set');
console.log('API_URL:', process.env.API_URL);
console.log('CORS_ORIGIN:', process.env.CORS_ORIGIN);

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cloudinary = require('cloudinary').v2;
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// ===== Health Check Endpoints (يجب أن تكون في البداية) =====
app.get('/health', (req, res) => {
  console.log('✅ Health check requested from:', req.ip);
  res.status(200).json({ 
    status: 'OK',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/api/health', (req, res) => {
  console.log('✅ API Health check requested from:', req.ip);
  res.status(200).json({ 
    status: 'OK',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Root endpoint for basic testing
app.get('/', (req, res) => {
  res.status(200).json({ 
    message: 'TabibiQ Backend API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// ===== إعدادات الأمان العامة =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
})); // حماية HTTP headers
app.use(mongoSanitize()); // منع NoSQL injection
app.use(express.json({ limit: '10mb' })); // تحديد حجم البيانات

// إضافة حماية من XSS
app.use((req, res, next) => {
  // تنظيف البيانات المدخلة
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = req.body[key].replace(/[<>]/g, '');
      }
    });
  }
  next();
});

// حماية من Log Injection
app.use((req, res, next) => {
  // تنظيف البيانات قبل التسجيل
  const sanitizedBody = { ...req.body };
  if (sanitizedBody.password) {
    sanitizedBody.password = '[REDACTED]';
  }
  if (sanitizedBody.token) {
    sanitizedBody.token = '[REDACTED]';
  }
  
  // تسجيل البيانات المُنظفة فقط
  console.log(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    body: sanitizedBody
  });
  
  next();
});

// حماية من HTTP Parameter Pollution
app.use((req, res, next) => {
  // تنظيف Query Parameters
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (Array.isArray(req.query[key])) {
        // إذا كان هناك قيم متعددة، خذ الأولى فقط
        req.query[key] = req.query[key][0];
      }
    });
  }
  
  // تنظيف Body Parameters - استثناء workTimes و vacationDays
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      // استثناء الحقول التي يجب أن تكون مصفوفات
      if (key === 'workTimes' || key === 'vacationDays') {
        return; // تخطي هذه الحقول
      }
      
      if (Array.isArray(req.body[key])) {
        // إذا كان هناك قيم متعددة، خذ الأولى فقط
        req.body[key] = req.body[key][0];
      }
    });
  }
  
  next();
});

// Middleware للتحقق من صحة البيانات
app.use((req, res, next) => {
  // التحقق من Content-Type - السماح بـ multipart/form-data للملفات
  if (req.method === 'POST' || req.method === 'PUT') {
    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('application/json') && !contentType.includes('multipart/form-data')) {
      return res.status(400).json({ error: 'Content-Type must be application/json or multipart/form-data' });
    }
  }
  
  // التحقق من حجم البيانات
  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 10 * 1024 * 1024) { // 10MB
    return res.status(413).json({ error: 'Payload too large' });
  }
  
  next();
});

// Rate Limiting - منع هجمات DDoS
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 100, // حد أقصى 100 طلب لكل IP
  message: { error: 'تم تجاوز الحد الأقصى للطلبات، يرجى المحاولة لاحقاً' },
  standardHeaders: true,
  legacyHeaders: false,
  // إضافة حماية إضافية
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  keyGenerator: (req) => {
    // استخدام IP + User-Agent لمنع التجاوز
    return req.ip + ':' + (req.headers['user-agent'] || 'unknown');
  }
});

// تطبيق Rate Limiting على جميع APIs
app.use('/api/', limiter);
app.use('/register', limiter);
app.use('/login', limiter);

// Rate Limiting أكثر صرامة للعمليات الحساسة
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 5, // حد أقصى 5 محاولات
  message: { error: 'تم تجاوز الحد الأقصى للمحاولات، يرجى المحاولة لاحقاً' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
});

// Rate Limiting للـ Brute Force
const bruteForceLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // ساعة واحدة
  max: 3, // حد أقصى 3 محاولات
  message: { error: 'تم اكتشاف محاولات متعددة، يرجى المحاولة بعد ساعة' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    res.status(429).json({
      error: 'تم اكتشاف محاولات متعددة',
      retryAfter: Math.ceil(60 * 60 / 1000) // ساعة واحدة
    });
  }
});

// تطبيق على العمليات الحساسة
app.use('/login', strictLimiter);
app.use('/register', strictLimiter);
app.use('/doctor-password', strictLimiter);
app.use('/user-password', strictLimiter);

// تطبيق Brute Force Limiter على العمليات الأكثر حساسية
app.use('/login', bruteForceLimiter);
app.use('/doctor-password', bruteForceLimiter);
app.use('/user-password', bruteForceLimiter);

// إعدادات CORS محسنة ومؤمنة - تدعم Vercel و Railway
const allowedOrigins = [
  'https://www.tabib-iq.com',
  'https://tabib-iq.com',
  'https://tabib-iq-frontend.vercel.app',
  'https://new-frontend-livid-beta.vercel.app',
  'https://new-frontend-hetxz9vv9-abubakers-projects-f1e3718d.vercel.app',
  'https://new-frontend-a1pslmpwn-abubakers-projects-f1e3718d.vercel.app',
  'http://localhost:3000'
];

app.use(cors({
  origin: function (origin, callback) {
    // إضافة debugging
    console.log('🌐 CORS check for origin:', origin);
    
    // السماح للطلبات بدون origin (مثل mobile apps)
    if (!origin) {
      console.log('✅ Allowing request without origin');
      return callback(null, true);
    }
    
    // السماح لأي رابط من Vercel (مطلوب للفرونت إند)
    if (origin.includes('vercel.app')) {
      console.log('✅ Allowing Vercel origin:', origin);
      return callback(null, true);
    }
    
    // السماح للنطاق الرئيسي tabib-iq.com
    if (origin.includes('tabib-iq.com')) {
      console.log('✅ Allowing tabib-iq.com origin:', origin);
      return callback(null, true);
    }
    
    // التحقق من النطاقات المسموحة الأخرى
    if (allowedOrigins.includes(origin)) {
      console.log('✅ Allowing allowed origin:', origin);
      callback(null, true);
    } else {
      console.log('🚫 Blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  // إضافة حماية إضافية
  maxAge: 86400 // cache preflight requests for 24 hours
}));

// إعداد مجلد رفع الصور
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// حماية من Directory Traversal مع إعدادات CORS للصور
app.use('/uploads', (req, res, next) => {
  const requestedPath = req.path;
  if (requestedPath.includes('..') || requestedPath.includes('//')) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // إعدادات CORS للصور
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Cache-Control', 'public, max-age=31536000000'); // كاش لمدة سنة
  res.header('Expires', new Date(Date.now() + 31536000000).toUTCString());
  
  // معالجة preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// إعدادات Multer محسنة للأمان
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // التأكد من وجود المجلد
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // إنشاء اسم ملف آمن وفريد
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    
    if (!allowedExtensions.includes(ext)) {
      return cb(new Error('نوع الملف غير مسموح به'), null);
    }
    
    cb(null, `upload-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // التحقق من نوع الملف
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('نوع الملف غير مسموح به'), false);
    }
  }
});

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
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
    console.log('✅ Cloudinary configured successfully');
  } catch (error) {
    console.error('❌ Cloudinary configuration error:', error);
  }
} else {
  console.log('⚠️ Cloudinary URL not found, using local storage');
}



// ===== إعدادات JWT =====
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// إعدادات JWT محسنة للأمان
const JWT_OPTIONS = {
  expiresIn: JWT_EXPIRES_IN,
  issuer: 'tabibiq-app',
  audience: 'tabibiq-users',
  algorithm: 'HS256'
};

// دالة إنشاء JWT token
const generateToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, JWT_OPTIONS);
};

// دالة التحقق من JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    // تأخير ثابت لمنع Timing Attacks
    setTimeout(() => {
      return res.status(401).json({ error: 'Access token required' });
    }, 100);
    return;
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('❌ JWT verification failed:', err.message);
      // تأخير ثابت لمنع Timing Attacks
      setTimeout(() => {
        return res.status(403).json({ error: 'Invalid or expired token' });
      }, 100);
      return;
    }
    req.user = user;
    next();
  });
};

// دالة التحقق من نوع المستخدم
const requireUserType = (allowedTypes) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!allowedTypes.includes(req.user.user_type)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

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

// Error Handler - منع تسريب المعلومات الحساسة
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  
  // في الإنتاج، لا تعرض تفاصيل الخطأ
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ 
      error: 'Internal Server Error',
      message: 'Something went wrong'
    });
  }
  
  // في التطوير، اعرض تفاصيل الخطأ
  res.status(500).json({ 
    error: err.message,
    stack: err.stack
  });
});



// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    security: {
      helmet: 'enabled',
      mongoSanitize: 'enabled',
      rateLimit: 'enabled',
      jwt: 'enabled',
      cors: 'restricted'
    }
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
  vacationDays: Array, // أيام الإجازات والأيام غير المتاحة
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
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // المستخدم الذي قام بالحجز
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor' },
  centerId: { type: mongoose.Schema.Types.ObjectId, ref: 'HealthCenter' }, // إضافة المركز
  serviceType: { type: String, enum: ['doctor', 'lab', 'xray', 'therapy', 'other'], default: 'doctor' }, // نوع الخدمة
  serviceName: String, // اسم الخدمة المحددة
  userName: String, // اسم المستخدم الذي قام بالحجز
  doctorName: String,
  centerName: String,
  date: String,
  time: String,
  reason: String,
  patientAge: { type: Number, min: 1, max: 120 }, // عمر المريض - إجباري
  status: { type: String, enum: ['pending', 'confirmed', 'cancelled', 'completed'], default: 'pending' },
  price: Number,
  notes: String,
  type: { type: String, enum: ['normal', 'special_appointment'], default: 'normal' },
  patientPhone: String, // رقم هاتف المريض
  patientName: String, // اسم المريض (قد يكون مختلف عن اسم المستخدم)
  isBookingForOther: { type: Boolean, default: false }, // هل الحجز لشخص آخر
  bookerName: String, // اسم الشخص الذي قام بالحجز
  duration: { type: Number, default: 30 }, // مدة الموعد بالدقائق
  attendance: { type: String, enum: ['present', 'absent'], default: 'absent' }, // حالة الحضور - فقط حاضر أو غائب
  attendanceTime: Date, // وقت تسجيل الحضور
  createdAt: { type: Date, default: Date.now }
});
const Appointment = mongoose.model('Appointment', appointmentSchema);

// مخطط الموظفين للأطباء
const employeeSchema = new mongoose.Schema({
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true }, // الطبيب المسؤول
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // المستخدم المرتبط (اختياري)
  phone: { type: String, required: true }, // رقم الهاتف العراقي
  name: { type: String, required: true }, // اسم الموظف
  email: String, // البريد الإلكتروني (اختياري)
  position: { type: String, default: 'موظف' }, // المنصب
  status: { type: String, enum: ['active', 'inactive', 'suspended'], default: 'active' }, // حالة الموظف
  hireDate: { type: Date, default: Date.now }, // تاريخ التعيين
  salary: Number, // الراتب
  commission: { type: Number, default: 0 }, // العمولة
  notes: String, // ملاحظات
  createdAt: { type: Date, default: Date.now }
});

// إنشاء فهرس فريد للموظف لكل طبيب
employeeSchema.index({ doctorId: 1, phone: 1 }, { unique: true });

const Employee = mongoose.model('Employee', employeeSchema);

// مخطط نظام النقاط
const pointsSchema = new mongoose.Schema({
  employeeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true }, // الموظف
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true }, // الطبيب
  appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' }, // الموعد المرتبط
  points: { type: Number, required: true }, // عدد النقاط
  type: { type: String, enum: ['appointment', 'attendance', 'bonus', 'deduction'], default: 'appointment' }, // نوع النقاط
  description: String, // وصف النقاط
  date: { type: Date, default: Date.now }, // تاريخ النقاط
  week: { type: Number }, // رقم الأسبوع
  month: { type: Number }, // رقم الشهر
  year: { type: Number } // السنة
});

const Points = mongoose.model('Points', pointsSchema);

// مخطط إحصائيات الموظفين
const employeeStatsSchema = new mongoose.Schema({
  employeeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee', required: true },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
  period: { type: String, enum: ['weekly', 'monthly', 'yearly'], required: true }, // الفترة
  startDate: { type: Date, required: Date.now }, // تاريخ البداية
  endDate: { type: Date, required: Date.now }, // تاريخ النهاية
  totalAppointments: { type: Number, default: 0 }, // إجمالي المواعيد
  attendedAppointments: { type: Number, default: 0 }, // المواعيد الحاضرة
  totalPoints: { type: Number, default: 0 }, // إجمالي النقاط
  averagePoints: { type: Number, default: 0 }, // متوسط النقاط
  lastUpdated: { type: Date, default: Date.now }
});

const EmployeeStats = mongoose.model('EmployeeStats', employeeStatsSchema);

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

// مخطط الإعلانات المتحركة
const advertisementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String, required: true }, // رابط الصورة من Cloudinary
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
  priority: { type: Number, default: 0 }, // الأولوية في العرض
  target: { 
    type: String, 
    enum: ['users', 'doctors', 'both'], 
    default: 'both' 
  },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  isFeatured: { type: Boolean, default: false },
  clicks: { type: Number, default: 0 }, // عدد النقرات
  views: { type: Number, default: 0 }, // عدد المشاهدات
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Advertisement = mongoose.model('Advertisement', advertisementSchema);

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
    console.log('📝 Register request body:', req.body);
    const { email, password, first_name, phone } = req.body;
    
    // التحقق من وجود جميع الحقول المطلوبة
    if (!email || !password || !first_name || !phone) {
      console.log('❌ Missing required fields:', { email: !!email, password: !!password, first_name: !!first_name, phone: !!phone });
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // توحيد رقم الهاتف
    const normPhone = normalizePhone(phone);
    console.log('📱 Normalized phone:', normPhone);
    
    // تحقق من وجود الإيميل في User أو Doctor (case-insensitive)
    const existingUser = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    const existingDoctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    
    if (existingUser || existingDoctor) {
      console.log('❌ Email already exists:', email);
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقًا' });
    }
    
    // تحقق من وجود رقم الهاتف في User أو Doctor
    const phoneUser = await User.findOne({ phone: normPhone });
    const phoneDoctor = await Doctor.findOne({ phone: normPhone });
    
    if (phoneUser || phoneDoctor) {
      console.log('❌ Phone already exists:', normPhone);
      return res.status(400).json({ error: 'رقم الهاتف مستخدم مسبقًا' });
    }
    
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, first_name, phone: normPhone });
    await user.save();
    
    console.log('✅ User created successfully:', { email, first_name, phone: normPhone });
    res.json({ message: 'تم إنشاء الحساب بنجاح!' });
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

// معالجة preflight request للتسجيل
app.options('/register-doctor', (req, res) => {
  // السماح لـ CORS العام بالعمل
  res.status(200).end();
});

// تسجيل طبيب جديد (مع إرسال الوثائق على الواتساب)
app.post('/register-doctor', upload.single('image'), async (req, res) => {
  // السماح لـ CORS العام بالعمل - لا حاجة لإضافة headers يدوياً
  
  try {
    console.log('👨‍⚕️ Doctor registration request received');
    console.log('📝 Request body:', req.body);
    console.log('📁 File:', req.file);
    
    const {
      email, password, name, phone, specialty, province, area, clinicLocation, mapLocation, about, workTimes
    } = req.body;
    
    // تنظيف البيانات
    const cleanEmail = email ? email.trim().toLowerCase() : '';
    const cleanName = name ? name.trim() : '';
    const cleanPhone = phone ? phone.trim() : '';
    const cleanSpecialty = specialty ? specialty.trim() : '';
    const cleanProvince = province ? province.trim() : '';
    const cleanArea = area ? area.trim() : '';
    const cleanClinicLocation = clinicLocation ? clinicLocation.trim() : '';
    const cleanMapLocation = mapLocation ? mapLocation.trim() : '';
    const cleanAbout = about ? about.trim() : '';
    
    // التحقق من الحقول المطلوبة
    if (!cleanEmail || !password || !cleanName || !cleanPhone || !cleanSpecialty || !cleanProvince || !cleanArea || !cleanClinicLocation) {
      console.log('❌ Missing required fields:', { 
        email: !!cleanEmail, 
        password: !!password, 
        name: !!cleanName, 
        phone: !!cleanPhone, 
        specialty: !!cleanSpecialty, 
        province: !!cleanProvince, 
        area: !!cleanArea, 
        clinicLocation: !!cleanClinicLocation 
      });
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // توحيد رقم الهاتف
    const normPhone = normalizePhone(cleanPhone);
    console.log('📱 Normalized phone:', normPhone);
    
    // تحقق من وجود الإيميل في قاعدة البيانات (case-insensitive)
    const existingDoctor = await Doctor.findOne({ email: { $regex: new RegExp(`^${cleanEmail}$`, 'i') } });
    const existingUser = await User.findOne({ email: { $regex: new RegExp(`^${cleanEmail}$`, 'i') } });
    
    if (existingDoctor || existingUser) {
      console.log('❌ Email already exists:', cleanEmail);
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقًا' });
    }
    
    // تحقق من وجود رقم الهاتف في User أو Doctor
    const phoneUser = await User.findOne({ phone: normPhone });
    const phoneDoctor = await Doctor.findOne({ phone: normPhone });
    if (phoneUser || phoneDoctor) {
      console.log('❌ Phone already exists:', normPhone);
      return res.status(400).json({ error: 'رقم الهاتف مستخدم مسبقًا' });
    }
    
    // تشفير كلمة المرور
    const hashed = await bcrypt.hash(password, 10);
    
    // مسار الصورة الشخصية فقط (اختيارية)
    const imagePath = req.file ? `/uploads/${req.file.filename}` : '';
    console.log('🖼️ Image path:', imagePath);
    
    // إنشاء الطبيب الجديد
    const doctor = new Doctor({
      email: cleanEmail,
      password: hashed,
      name: formatDoctorName(cleanName), // إضافة "د." تلقائياً
      phone: normPhone,
      specialty: cleanSpecialty,
      province: cleanProvince,
      area: cleanArea,
      clinicLocation: cleanClinicLocation,
      mapLocation: cleanMapLocation, // رابط الموقع على الخريطة
      image: imagePath, // الصورة الشخصية فقط
      about: cleanAbout,
      workTimes: (() => {
        let parsedWorkTimes = workTimes ? (typeof workTimes === 'string' ? JSON.parse(workTimes) : workTimes) : [];
        // تنسيق workTimes للشكل المطلوب من قاعدة البيانات
        return parsedWorkTimes.map(wt => ({
          day: wt.day,
          from: wt.from,
          to: wt.to,
          start_time: wt.start_time || wt.from,
          end_time: wt.end_time || wt.to,
          is_available: wt.is_available !== undefined ? wt.is_available : true
        }));
      })(),
      experienceYears: req.body.experienceYears ? Number(req.body.experienceYears) : 0,
      appointmentDuration: req.body.appointmentDuration ? Number(req.body.appointmentDuration) : 30,
      user_type: 'doctor',
      status: 'pending', // في انتظار إرسال الوثائق
      created_at: new Date(),
      createdAt: new Date()
    });
    
    console.log('💾 Saving doctor to database...');
    console.log('📋 Doctor data to save:', {
      email: cleanEmail,
      name: formatDoctorName(cleanName),
      phone: normPhone,
      specialty: cleanSpecialty,
      province: cleanProvince,
      area: cleanArea,
      clinicLocation: cleanClinicLocation,
      workTimes: workTimes ? (typeof workTimes === 'string' ? JSON.parse(workTimes) : workTimes) : []
    });
    
    await doctor.save();
    console.log('✅ Doctor saved successfully:', doctor._id);
    
    // إنشاء رابط الواتساب لإرسال الوثائق
    const whatsappNumber = '+9647769012619';
    const doctorInfo = `👨‍⚕️ طبيب جديد: ${formatDoctorName(cleanName)}\n📧 البريد: ${cleanEmail}\n📱 الهاتف: ${normPhone}\n🏥 التخصص: ${cleanSpecialty}\n📍 المحافظة: ${cleanProvince}`;
    
    const whatsappMessage = encodeURIComponent(`مرحباً! 👋

${doctorInfo}

📋 المطلوب إرساله:
1️⃣ صورة الهوية الشخصية (الوجه)
2️⃣ صورة الهوية الشخصية (الظهر)  
3️⃣ صورة شهادة النقابة (الوجه)
4️⃣ صورة شهادة النقابة (الظهر)

📞 رقم الهاتف: ${normPhone}
📧 البريد الإلكتروني: ${cleanEmail}

شكراً لك! 🙏`);

    const whatsappLink = `https://wa.me/${whatsappNumber}?text=${whatsappMessage}`;
    
    console.log('✅ Doctor registration completed successfully');
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
    console.error('❌ Doctor registration error:', err);
    
    // معالجة أفضل للأخطاء
    let errorMessage = 'حدث خطأ أثناء إنشاء الحساب';
    
    if (err.name === 'ValidationError') {
      errorMessage = 'بيانات غير صحيحة: ' + Object.values(err.errors).map(e => e.message).join(', ');
    } else if (err.name === 'MongoError' && err.code === 11000) {
      errorMessage = 'البريد الإلكتروني أو رقم الهاتف مستخدم مسبقاً';
    } else if (err.message) {
      errorMessage = err.message;
    }
    
    res.status(500).json({ error: errorMessage });
  }
});

// تسجيل الدخول (حسب نوع الحساب)
app.post('/login', async (req, res) => {
  try {
    console.log('🔐 Login request body:', req.body);
    let { email, password, loginType } = req.body;
    
    // التحقق من وجود جميع الحقول المطلوبة
    if (!email || !password || !loginType) {
      console.log('❌ Missing required fields:', { email: !!email, password: !!password, loginType: !!loginType });
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // إذا كان input لا يحتوي @ اعتبره رقم هاتف
    let isPhone = false;
    if (email && !email.includes('@')) {
      isPhone = true;
      email = normalizePhone(email);
      console.log('📱 Normalized phone for login:', email);
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
          
          // إنشاء JWT token
          const token = generateToken(adminUser);
          
          return res.json({ 
            message: 'تم تسجيل الدخول بنجاح', 
            userType: 'admin', 
            user: adminUser,
            token: token
          });
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
        
        // إنشاء JWT token
        const token = generateToken(doctorObj);
        
        return res.json({ 
          message: 'تم تسجيل الدخول بنجاح', 
          userType: 'doctor', 
          doctor: doctorObj,
          token: token
        });
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
        
        // إنشاء JWT token
        const token = generateToken(userObj);
        
        return res.json({ 
          message: 'تم تسجيل الدخول بنجاح', 
          userType: 'user', 
          user: userObj,
          token: token
        });
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
    console.error('❌ Login error:', err);
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
    
    // التحقق من صحة doctorId
    if (!mongoose.Types.ObjectId.isValid(doctorId)) {
      return res.status(400).json({ error: 'معرف الطبيب غير صحيح' });
    }
    
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
    
    // إضافة معلومات إضافية للحجز لشخص آخر
    const enhancedAppointments = uniqueAppointments.map(appointment => {
      const enhanced = { ...appointment };
      
      // إذا كان الحجز لشخص آخر، أضف معلومات إضافية
      if (appointment.isBookingForOther) {
        enhanced.displayInfo = {
          patientName: appointment.patientName || 'غير محدد',
          patientAge: appointment.patientAge || 'غير محدد',
          patientPhone: appointment.patientPhone || 'غير محدد',
          bookerName: appointment.bookerName || appointment.userName || 'غير محدد',
          isBookingForOther: true,
          message: `الحجز من قبل: ${appointment.bookerName || appointment.userName} للمريض: ${appointment.patientName}`
        };
      } else {
        enhanced.displayInfo = {
          patientName: appointment.userName || 'غير محدد',
          patientAge: appointment.patientAge || 'غير محدد',
          patientPhone: appointment.userId?.phone || 'غير محدد',
          bookerName: appointment.userName || 'غير محدد',
          isBookingForOther: false,
          message: `الحجز من قبل: ${appointment.userName}`
        };
      }
      
      return enhanced;
    });
    
    console.log(`🔍 مواعيد الطبيب ${doctorId}:`);
    console.log(`   - المواعيد الأصلية: ${allAppointments.length}`);
    console.log(`   - المواعيد بعد إزالة التكرار: ${uniqueAppointments.length}`);
    
    res.json(enhancedAppointments);
  } catch (err) {
    console.error('❌ Error fetching doctor appointments:', err);
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

// جلب قائمة المستخدمين - محمي بـ JWT
app.get('/users', authenticateToken, requireUserType(['admin']), async (req, res) => {
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
      .populate('doctorId', 'name specialty province area image profileImage about workTimes experienceYears phone clinicLocation mapLocation status active createdAt disabled')
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

// جلب جميع الأطباء (للإدارة - يشمل المعلقين مع جميع البيانات) - محمي بـ JWT
app.get('/admin/doctors', authenticateToken, requireUserType(['admin']), async (req, res) => {
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
app.post('/admin/health-centers', authenticateToken, requireUserType(['admin']), async (req, res) => {
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
app.get('/admin/health-centers', authenticateToken, requireUserType(['admin']), async (req, res) => {
  try {
    const centers = await HealthCenter.find({}, { password: 0, __v: 0 })
      .sort({ createdAt: -1 });
    
    res.json(centers);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب المراكز الصحية' });
  }
});

// إضافة طبيب لمركز صحي
app.post('/admin/health-centers/:centerId/doctors', authenticateToken, requireUserType(['admin']), async (req, res) => {
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

// حجز موعد جديد (يدعم الحجز لشخص آخر)
app.post('/appointments', async (req, res) => {
  try {
    const { 
      userId, 
      doctorId, 
      userName, 
      doctorName, 
      date, 
      time, 
      reason, 
      patientAge, 
      duration,
      patientName, // اسم المريض (قد يكون مختلف عن اسم المستخدم)
      patientPhone, // رقم هاتف المريض
      isBookingForOther, // هل الحجز لشخص آخر
      bookerName // اسم الشخص الذي قام بالحجز
    } = req.body;
    
    if (!userId || !doctorId || !date || !time || !patientAge) {
      return res.status(400).json({ error: 'البيانات ناقصة - العمر مطلوب' });
    }
    
    // التحقق من صحة العمر
    if (patientAge < 1 || patientAge > 120) {
      return res.status(400).json({ error: 'العمر يجب أن يكون بين 1 و 120 سنة' });
    }
    
    // إذا كان الحجز لشخص آخر، تأكد من وجود اسم المريض
    if (isBookingForOther && !patientName) {
      return res.status(400).json({ error: 'اسم المريض مطلوب عند الحجز لشخص آخر' });
    }
    
    // جلب معلومات الطبيب للتحقق من أيام الإجازات
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    // التحقق من أن التاريخ ليس يوم إجازة
    const dateObj = new Date(date);
    if (isVacationDay(dateObj, doctor.vacationDays)) {
      return res.status(400).json({ error: 'لا يمكن الحجز في هذا اليوم لأنه يوم إجازة للطبيب' });
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
    
    // تحديد اسم المريض النهائي
    const finalPatientName = isBookingForOther ? patientName : userName;
    const finalBookerName = isBookingForOther ? (bookerName || userName) : userName;
    
    const appointment = new Appointment({
      userId,
      doctorId: new mongoose.Types.ObjectId(doctorId),
      userName: finalBookerName, // اسم الشخص الذي قام بالحجز
      doctorName: formatDoctorName(doctorName), // إضافة "د." تلقائياً
      date,
      time,
      reason,
      patientAge: Number(patientAge), // عمر المريض
      patientName: finalPatientName, // اسم المريض
      patientPhone: patientPhone || '', // رقم هاتف المريض
      isBookingForOther: isBookingForOther || false, // هل الحجز لشخص آخر
      bookerName: finalBookerName, // اسم الشخص الذي قام بالحجز
      duration: duration ? Number(duration) : 30 // مدة الموعد بالدقائق
    });
    
    await appointment.save();
    
    // إشعار للدكتور عند حجز موعد جديد
    try {
      let notificationMessage;
      if (isBookingForOther) {
        notificationMessage = `تم حجز موعد جديد من قبل ${finalBookerName} للمريض ${finalPatientName} (عمر: ${patientAge}) في ${date} الساعة ${time}`;
      } else {
        notificationMessage = `تم حجز موعد جديد من قبل ${finalPatientName} في ${date} الساعة ${time}`;
      }
      
      const notification = await Notification.create({
        doctorId: new mongoose.Types.ObjectId(doctorId),
        type: 'new_appointment',
        message: notificationMessage
      });

    } catch (notificationError) {
      // لا نوقف العملية إذا فشل إنشاء الإشعار
      console.error('❌ Notification error:', notificationError);
    }
    
    res.json({ 
      message: 'تم حجز الموعد بنجاح', 
      appointment,
      bookingInfo: {
        isForOther: isBookingForOther,
        patientName: finalPatientName,
        bookerName: finalBookerName
      }
    });
  } catch (err) {
    console.error('❌ Appointment booking error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حجز الموعد' });
  }
});

// مسار للحصول على معلومات الحجز لشخص آخر
app.get('/appointment-details/:appointmentId', async (req, res) => {
  try {
    const { appointmentId } = req.params;
    
    const appointment = await Appointment.findById(appointmentId)
      .populate('userId', 'first_name phone')
      .populate('doctorId', 'name specialty');
    
    if (!appointment) {
      return res.status(404).json({ error: 'الموعد غير موجود' });
    }
    
    // تجهيز معلومات العرض
    const displayInfo = {
      appointmentId: appointment._id,
      date: appointment.date,
      time: appointment.time,
      doctorName: appointment.doctorName,
      doctorSpecialty: appointment.doctorId?.specialty,
      reason: appointment.reason,
      status: appointment.status,
      duration: appointment.duration,
      isBookingForOther: appointment.isBookingForOther || false
    };
    
    if (appointment.isBookingForOther) {
      // إذا كان الحجز لشخص آخر
      displayInfo.patientInfo = {
        name: appointment.patientName,
        age: appointment.patientAge,
        phone: appointment.patientPhone
      };
      displayInfo.bookerInfo = {
        name: appointment.bookerName || appointment.userName,
        phone: appointment.userId?.phone
      };
      displayInfo.message = `الحجز من قبل: ${appointment.bookerName || appointment.userName} للمريض: ${appointment.patientName}`;
    } else {
      // إذا كان الحجز للشخص نفسه
      displayInfo.patientInfo = {
        name: appointment.userName,
        age: appointment.patientAge,
        phone: appointment.userId?.phone
      };
      displayInfo.bookerInfo = {
        name: appointment.userName,
        phone: appointment.userId?.phone
      };
      displayInfo.message = `الحجز من قبل: ${appointment.userName}`;
    }
    
    res.json({
      success: true,
      appointment: displayInfo
    });
    
  } catch (err) {
    console.error('❌ Error fetching appointment details:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب تفاصيل الموعد' });
  }
});

// حجز موعد لشخص آخر (بدون رسالة "الحجز لشخص آخر")
app.post('/appointments-for-other', async (req, res) => {
  try {
    const { 
      userId, 
      doctorId, 
      userName, 
      doctorName, 
      date, 
      time, 
      reason, 
      patientAge, 
      duration,
      patientName, // اسم المريض (مطلوب)
      patientPhone, // رقم هاتف المريض
      bookerName // اسم الشخص الذي قام بالحجز
    } = req.body;
    
    if (!userId || !doctorId || !date || !time || !patientAge || !patientName) {
      return res.status(400).json({ error: 'البيانات ناقصة - العمر واسم المريض مطلوبان' });
    }
    
    // التحقق من صحة العمر
    if (patientAge < 1 || patientAge > 120) {
      return res.status(400).json({ error: 'العمر يجب أن يكون بين 1 و 120 سنة' });
    }
    
    // جلب معلومات الطبيب للتحقق من أيام الإجازات
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    // التحقق من أن التاريخ ليس يوم إجازة
    const dateObj = new Date(date);
    if (isVacationDay(dateObj, doctor.vacationDays)) {
      return res.status(400).json({ error: 'لا يمكن الحجز في هذا اليوم لأنه يوم إجازة للطبيب' });
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
      userName: bookerName || userName, // اسم الشخص الذي قام بالحجز
      doctorName: formatDoctorName(doctorName), // إضافة "د." تلقائياً
      date,
      time,
      reason,
      patientAge: Number(patientAge), // عمر المريض
      patientName: patientName, // اسم المريض
      patientPhone: patientPhone || '', // رقم هاتف المريض
      isBookingForOther: true, // تأكيد أن الحجز لشخص آخر
      bookerName: bookerName || userName, // اسم الشخص الذي قام بالحجز
      duration: duration ? Number(duration) : 30 // مدة الموعد بالدقائق
    });
    
    await appointment.save();
    
    // إشعار للدكتور عند حجز موعد جديد
    try {
      const notificationMessage = `تم حجز موعد جديد من قبل ${bookerName || userName} للمريض ${patientName} (عمر: ${patientAge}) في ${date} الساعة ${time}`;
      
      const notification = await Notification.create({
        doctorId: new mongoose.Types.ObjectId(doctorId),
        type: 'new_appointment',
        message: notificationMessage
      });

    } catch (notificationError) {
      // لا نوقف العملية إذا فشل إنشاء الإشعار
      console.error('❌ Notification error:', notificationError);
    }
    
    res.json({ 
      message: 'تم حجز الموعد بنجاح', 
      appointment,
      bookingInfo: {
        patientName: patientName,
        bookerName: bookerName || userName
      }
    });
  } catch (err) {
    console.error('❌ Appointment booking for other error:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء حجز الموعد' });
  }
});

// مسار للحصول على إحصائيات الحجز لشخص آخر
app.get('/appointments-stats/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    
    // إجمالي المواعيد
    const totalAppointments = await Appointment.countDocuments({ doctorId });
    
    // المواعيد للحجز لشخص آخر
    const bookingsForOthers = await Appointment.countDocuments({ 
      doctorId, 
      isBookingForOther: true 
    });
    
    // المواعيد للحجز للشخص نفسه
    const selfBookings = await Appointment.countDocuments({ 
      doctorId, 
      isBookingForOther: { $ne: true } 
    });
    
    // المواعيد حسب الحالة
    const statusStats = await Appointment.aggregate([
      { $match: { doctorId: new mongoose.Types.ObjectId(doctorId) } },
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
    
    // المواعيد حسب التاريخ (آخر 7 أيام)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentBookings = await Appointment.countDocuments({
      doctorId,
      createdAt: { $gte: sevenDaysAgo }
    });
    
    res.json({
      success: true,
      stats: {
        total: totalAppointments,
        forOthers: bookingsForOthers,
        selfBookings: selfBookings,
        statusBreakdown: statusStats,
        recentBookings: recentBookings,
        percentageForOthers: totalAppointments > 0 ? Math.round((bookingsForOthers / totalAppointments) * 100) : 0
      }
    });
    
  } catch (err) {
    console.error('❌ Error fetching appointment stats:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب إحصائيات المواعيد' });
  }
});

// جلب المواعيد المحجوزة لطبيب معين في تاريخ محدد
app.get('/appointments/:doctorId/:date', async (req, res) => {
  try {
    const { doctorId, date } = req.params;
    
    // جلب معلومات الطبيب للتحقق من أيام الإجازات
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    // التحقق من أن التاريخ ليس يوم إجازة
    const dateObj = new Date(date);
    if (isVacationDay(dateObj, doctor.vacationDays)) {
      return res.json([]); // إرجاع قائمة فارغة لأن اليوم هو يوم إجازة
    }
    
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
    
    // إضافة معلومات إضافية للحجز لشخص آخر
    const enhancedAppointments = uniqueAppointments.map(appointment => {
      const enhanced = { ...appointment };
      
      // إذا كان الحجز لشخص آخر، أضف معلومات إضافية
      if (appointment.isBookingForOther) {
        enhanced.displayInfo = {
          patientName: appointment.patientName || 'غير محدد',
          patientAge: appointment.patientAge || 'غير محدد',
          patientPhone: appointment.patientPhone || 'غير محدد',
          bookerName: appointment.bookerName || appointment.userName || 'غير محدد',
          isBookingForOther: true,
          message: `الحجز من قبل: ${appointment.bookerName || appointment.userName} للمريض: ${appointment.patientName}`
        };
      } else {
        enhanced.displayInfo = {
          patientName: appointment.userName || 'غير محدد',
          patientAge: appointment.patientAge || 'غير محدد',
          patientPhone: appointment.userId?.phone || 'غير محدد',
          bookerName: appointment.userName || 'غير محدد',
          isBookingForOther: false,
          message: `الحجز من قبل: ${appointment.userName}`
        };
      }
      
      return enhanced;
    });
    
    console.log(`🔍 مواعيد الطبيب ${doctorId}:`);
    console.log(`   - المواعيد الأصلية: ${allAppointments.length}`);
    console.log(`   - المواعيد بعد إزالة التكرار: ${uniqueAppointments.length}`);
    
    res.json(enhancedAppointments);
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
    
    // إرسال إشعار للمريض عند إلغاء الموعد
    try {
      let notificationMessage;
      if (appointment.isBookingForOther) {
        notificationMessage = `تم إلغاء موعدك مع ${appointment.doctorName} في ${appointment.date} الساعة ${appointment.time}. يرجى اختيار موعد آخر.`;
      } else {
        notificationMessage = `تم إلغاء موعدك مع ${appointment.doctorName} في ${appointment.date} الساعة ${appointment.time}. يرجى اختيار موعد آخر.`;
      }
      
      // إنشاء إشعار للمريض
      const patientNotification = await Notification.create({
        userId: appointment.userId,
        type: 'appointment_cancelled',
        message: notificationMessage
      });
      
      console.log(`✅ تم إرسال إشعار إلغاء الموعد للمريض: ${appointment.patientName || appointment.userName}`);
      
    } catch (notificationError) {
      // لا نوقف العملية إذا فشل إنشاء الإشعار
      console.error('❌ Notification error:', notificationError);
    }
    
    // إذا كان الحجز لشخص آخر، أضف معلومات إضافية
    let message = 'تم إلغاء الموعد بنجاح';
    if (appointment.isBookingForOther) {
      message = `تم إلغاء موعد المريض ${appointment.patientName} الذي كان محجوز من قبل ${appointment.bookerName}`;
    }
    
    res.json({ 
      message: message,
      cancelledAppointment: {
        id: appointment._id,
        patientName: appointment.patientName || appointment.userName,
        bookerName: appointment.bookerName || appointment.userName,
        date: appointment.date,
        time: appointment.time,
        isBookingForOther: appointment.isBookingForOther
      }
    });
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
    
    // استخدام كل الحقول المرسلة في body
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

    // إحصائيات الحضور والغياب
    const attendanceStats = await Appointment.aggregate([
      { $match: { doctorId: new mongoose.Types.ObjectId(doctorId) } },
      {
        $group: {
          _id: '$attendance',
          count: { $sum: 1 }
        }
      }
    ]);

    // تحويل النتائج إلى كائن
    const attendanceData = {};
    attendanceStats.forEach(stat => {
      attendanceData[stat._id] = stat.count;
    });

    // حساب النسب المئوية
    const presentCount = attendanceData.present || 0;
    const absentCount = attendanceData.absent || 0;
    const pendingCount = attendanceData.pending || 0;
    const totalWithAttendance = presentCount + absentCount + pendingCount;
    
    const attendancePercentages = {
      present: totalWithAttendance > 0 ? ((presentCount / totalWithAttendance) * 100).toFixed(1) : 0,
      absent: totalWithAttendance > 0 ? ((absentCount / totalWithAttendance) * 100).toFixed(1) : 0,
      pending: totalWithAttendance > 0 ? ((pendingCount / totalWithAttendance) * 100).toFixed(1) : 0
    };

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
        dailyAppointments,
        attendanceStats: attendanceData,
        attendancePercentages
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
app.get('/api/users', authenticateToken, requireUserType(['admin']), async (req, res) => {
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
app.get('/api/doctors', authenticateToken, requireUserType(['admin']), async (req, res) => {
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
app.get('/api/appointments', authenticateToken, requireUserType(['admin']), async (req, res) => {
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
    const { status, employeeId } = req.body;
    
    const appointment = await Appointment.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ error: 'الموعد غير موجود' });
    }
    
    // إضافة نقاط تلقائياً إذا تم تأكيد الموعد وتم تحديد موظف
    if (status === 'confirmed' && employeeId) {
      try {
        // التحقق من أن الموظف موجود
        const employee = await Employee.findById(employeeId);
        if (employee && employee.doctorId.toString() === appointment.doctorId.toString()) {
          // إضافة 3 نقاط للموعد المؤكد
          const pointsRecord = new Points({
            employeeId,
            doctorId: appointment.doctorId,
            appointmentId: appointment._id,
            points: 3,
            type: 'appointment',
            description: `موعد مؤكد - ${appointment.patientName || appointment.userName}`,
            date: new Date()
          });
          
          await pointsRecord.save();
          
          // تحديث إحصائيات الموظف
          await updateEmployeeStats(employeeId, appointment.doctorId);
          
          console.log(`تم إضافة 3 نقاط للموظف ${employee.name} للموعد ${appointment._id}`);
        }
      } catch (pointsError) {
        console.error('خطأ في إضافة النقاط:', pointsError);
        // لا نوقف العملية إذا فشل إضافة النقاط
      }
    }
    
    res.json({ message: 'تم تحديث حالة الموعد بنجاح', appointment });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في تحديث حالة الموعد' });
  }
});

// تحديث حالة الحضور
app.put('/api/appointments/:id/attendance', async (req, res) => {
  try {
    const { id } = req.params;
    const { attendance, employeeId } = req.body;
    
    // التأكد من أن القيمة صحيحة
    if (attendance !== 'present' && attendance !== 'absent') {
      return res.status(400).json({ error: 'قيمة غير صحيحة لحالة الحضور' });
    }
    
    const updateData = { attendance };
    if (attendance === 'present') {
      updateData.attendanceTime = new Date();
    }
    
    const appointment = await Appointment.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    );
    
    if (!appointment) {
      return res.status(404).json({ error: 'الموعد غير موجود' });
    }
    
    // إضافة نقاط إضافية عند الحضور إذا تم تحديد موظف
    if (attendance === 'present' && employeeId) {
      try {
        // التحقق من أن الموظف موجود
        const employee = await Employee.findById(employeeId);
        if (employee && employee.doctorId.toString() === appointment.doctorId.toString()) {
          // إضافة نقاط إضافية للحضور
          const pointsRecord = new Points({
            employeeId,
            doctorId: appointment.doctorId,
            appointmentId: appointment._id,
            points: 2, // نقاط إضافية للحضور
            type: 'attendance',
            description: `حضور المريض - ${appointment.patientName || appointment.userName}`,
            date: new Date()
          });
          
          await pointsRecord.save();
          
          // تحديث إحصائيات الموظف
          await updateEmployeeStats(employeeId, appointment.doctorId);
          
          console.log(`تم إضافة نقاط حضور للموظف ${employee.name} للموعد ${appointment._id}`);
        }
      } catch (pointsError) {
        console.error('خطأ في إضافة نقاط الحضور:', pointsError);
        // لا نوقف العملية إذا فشل إضافة النقاط
      }
    }
    
    res.json({ message: 'تم تحديث حالة الحضور بنجاح', appointment });
  } catch (error) {
    res.status(500).json({ error: 'خطأ في تحديث حالة الحضور' });
  }
});

// جلب التحليل والإحصائيات
app.get('/api/analytics', async (req, res) => {
  try {
    // إحصائيات الحضور والغياب
    const attendanceStats = await Appointment.aggregate([
      {
        $group: {
          _id: '$attendance',
          count: { $sum: 1 }
        }
      }
    ]);

    // تحويل النتائج إلى كائن مع القيم الافتراضية
    const attendanceData = {
      present: 0,
      absent: 0
    };
    attendanceStats.forEach(stat => {
      if (stat._id === 'present' || stat._id === 'absent') {
        attendanceData[stat._id] = stat.count;
      }
    });

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
      userGrowth,
      attendanceStats: attendanceData
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

// ==================== APIs إدارة الإعلانات المتحركة ====================

// جلب الإعلانات النشطة حسب الفئة المستهدفة
app.get('/advertisements/:target', async (req, res) => {
  try {
    const { target } = req.params;
    const currentDate = new Date();
    
    console.log('🔍 طلب جلب إعلانات للفئة:', target);
    
    let query = {
      status: 'active'
      // startDate: { $lte: currentDate },  // مؤقتاً للاختبار
      // endDate: { $gte: currentDate }     // مؤقتاً للاختبار
    };
    
    // تحديد الفئة المستهدفة
    if (target === 'users') {
      query.target = { $in: ['users', 'both'] };
    } else if (target === 'doctors') {
      query.target = { $in: ['doctors', 'both'] };
    }
    
    console.log('📊 الاستعلام المستخدم:', JSON.stringify(query));
    
    // أولاً: جلب جميع الإعلانات للتحقق
    const allAds = await Advertisement.find({});
    console.log('📋 جميع الإعلانات في قاعدة البيانات:', allAds.length);
    console.log('📝 تفاصيل الإعلانات:', allAds.map(ad => ({
      id: ad._id,
      title: ad.title,
      status: ad.status,
      target: ad.target,
      startDate: ad.startDate,
      endDate: ad.endDate
    })));
    
    const advertisements = await Advertisement.find(query)
      .sort({ priority: -1, isFeatured: -1, createdAt: -1 })
      .limit(10);
    
    console.log('✅ الإعلانات المطابقة للاستعلام:', advertisements.length);
    console.log('📤 إرسال الإعلانات:', advertisements.map(ad => ({
      id: ad._id,
      title: ad.title,
      status: ad.status,
      target: ad.target
    })));
    
    res.json(advertisements);
  } catch (err) {
    console.error('❌ خطأ في جلب الإعلانات:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الإعلانات' });
  }
});

// جلب جميع الإعلانات (للوحة تحكم الأدمن)
app.get('/admin/advertisements', authenticateToken, requireUserType(['admin']), async (req, res) => {
  try {
    const advertisements = await Advertisement.find({})
      .sort({ createdAt: -1 });
    res.json(advertisements);
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء جلب الإعلانات' });
  }
});

// إضافة إعلان جديد
app.post('/admin/advertisements', authenticateToken, requireUserType(['admin']), async (req, res) => {
  try {
    const {
      title,
      description,
      image,
      type,
      target,
      startDate,
      endDate,
      priority,
      isFeatured
    } = req.body;
    
    // التحقق من البيانات المطلوبة
    if (!title || !description || !image || !target || !startDate || !endDate) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }
    
    // التحقق من صحة التواريخ
    if (new Date(startDate) >= new Date(endDate)) {
      return res.status(400).json({ error: 'تاريخ البداية يجب أن يكون قبل تاريخ النهاية' });
    }
    
    const advertisement = new Advertisement({
      title,
      description,
      image,
      type: type || 'announcement',
      target,
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      priority: priority || 0,
      isFeatured: isFeatured || false,
      createdBy: req.body.adminId // سيتم إرساله من الواجهة الأمامية
    });
    
    await advertisement.save();
    res.json({ message: 'تم إضافة الإعلان بنجاح', advertisement });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء إضافة الإعلان' });
  }
});

// تحديث إعلان
app.put('/admin/advertisements/:id', authenticateToken, requireUserType(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updatedAt: new Date() };
    
    // التحقق من صحة التواريخ إذا تم تحديثها
    if (updateData.startDate && updateData.endDate) {
      if (new Date(updateData.startDate) >= new Date(updateData.endDate)) {
        return res.status(400).json({ error: 'تاريخ البداية يجب أن يكون قبل تاريخ النهاية' });
      }
    }
    
    const advertisement = await Advertisement.findByIdAndUpdate(id, updateData, { new: true });
    if (!advertisement) {
      return res.status(404).json({ error: 'الإعلان غير موجود' });
    }
    
    res.json({ message: 'تم تحديث الإعلان بنجاح', advertisement });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث الإعلان' });
  }
});

// حذف إعلان
app.delete('/admin/advertisements/:id', authenticateToken, requireUserType(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const advertisement = await Advertisement.findByIdAndDelete(id);
    
    if (!advertisement) {
      return res.status(404).json({ error: 'الإعلان غير موجود' });
    }
    
    res.json({ message: 'تم حذف الإعلان بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء حذف الإعلان' });
  }
});

// تحديث إحصائيات الإعلان (النقرات والمشاهدات)
app.post('/advertisements/:id/stats', async (req, res) => {
  try {
    const { id } = req.params;
    const { action } = req.body; // 'view' أو 'click'
    
    const updateData = {};
    if (action === 'view') {
      updateData.$inc = { views: 1 };
    } else if (action === 'click') {
      updateData.$inc = { clicks: 1 };
    }
    
    await Advertisement.findByIdAndUpdate(id, updateData);
    res.json({ message: 'تم تحديث الإحصائيات بنجاح' });
  } catch (err) {
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث الإحصائيات' });
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
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
  console.log(`🔗 API Health check: http://localhost:${PORT}/api/health`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`⏰ Started at: ${new Date().toISOString()}`);
  console.log(`🔧 Process ID: ${process.pid}`);
  console.log(`🌍 Server URL: ${process.env.API_URL || `http://localhost:${PORT}`}`);
});

// Handle server errors
server.on('error', (error) => {
  console.error('❌ Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error('🔍 Port is already in use. Please try a different port.');
  } else if (error.code === 'EACCES') {
    console.error('🔒 Permission denied. Try running with elevated privileges.');
  } else if (error.code === 'EADDRNOTAVAIL') {
    console.error('🌐 Address not available. Check your network configuration.');
  }
  
  // Exit gracefully on critical errors
  process.exit(1);
});

// Unhandled error handling
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
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

// Endpoint لرفع صور الإعلانات
app.post('/upload-advertisement-image', upload.single('image'), async (req, res) => {
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
        console.log('🔄 Attempting to upload advertisement image to Cloudinary...');
        const result = await cloudinary.uploader.upload(req.file.path, {
          folder: 'tabibiq-advertisements',
          transformation: [
            { width: 800, height: 300, crop: 'fill' }, // الأبعاد المطلوبة للإعلانات
            { quality: 'auto', fetch_format: 'auto' }
          ],
          resource_type: 'image'
        });
        imageUrl = result.secure_url;
        uploadSuccess = true;
        console.log('✅ Advertisement image uploaded to Cloudinary successfully:', imageUrl);
        
        // حذف الملف المحلي بعد رفعه إلى Cloudinary
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
          console.log('🗑️ Local file deleted after Cloudinary upload');
        }
      } catch (cloudinaryError) {
        console.error('❌ Cloudinary upload failed for advertisement:', cloudinaryError);
        // إذا فشل Cloudinary، استخدم التخزين المحلي
        const baseUrl = process.env.API_URL || `${req.protocol}://${req.get('host')}`;
        imageUrl = `${baseUrl}/uploads/${req.file.filename}`;
        console.log('📁 Using local storage as fallback for advertisement:', imageUrl);
      }
    } else {
      // استخدام التخزين المحلي إذا لم يتم إعداد Cloudinary
      const baseUrl = process.env.API_URL || `${req.protocol}://${req.get('host')}`;
      imageUrl = `${baseUrl}/uploads/${req.file.filename}`;
      console.log('📁 Using local storage for advertisement:', imageUrl);
    }
    
    res.json({ 
      success: true, 
      imageUrl,
      uploadSuccess,
      message: 'تم رفع صورة الإعلان بنجاح' 
    });
  } catch (err) {
    console.error('❌ Error in advertisement image upload:', err);
    
    // حذف الملف المحلي في حالة الخطأ
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('🗑️ Local file deleted due to error');
      } catch (deleteError) {
        console.error('❌ Error deleting local file:', deleteError);
      }
    }
    
    res.status(500).json({ error: 'حدث خطأ أثناء رفع صورة الإعلان' });
  }
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
app.post('/admin/toggle-account/:type/:id', authenticateToken, requireUserType(['admin']), async (req, res) => {
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

    // التحقق من أن أوقات الدوام تحتوي على البيانات المطلوبة
    if (workTimes.length > 0) {
      const invalidWorkTimes = workTimes.filter(wt => 
        !wt || typeof wt !== 'object' || !wt.day || !wt.from || !wt.to || !wt.start_time || !wt.end_time
      );
      
      if (invalidWorkTimes.length > 0) {
        console.error('❌ بيانات أوقات الدوام غير صحيحة:', invalidWorkTimes);
        return res.status(400).json({ error: 'بيانات أوقات الدوام غير صحيحة - يرجى التأكد من إدخال جميع البيانات المطلوبة' });
      }
    }

    // تنسيق workTimes للشكل المطلوب من قاعدة البيانات
    const formattedWorkTimes = workTimes.map(wt => ({
      day: wt.day,
      from: wt.from,
      to: wt.to,
      start_time: wt.start_time || wt.from,
      end_time: wt.end_time || wt.to,
      is_available: wt.is_available !== undefined ? wt.is_available : true
    }));

    const doctor = await Doctor.findByIdAndUpdate(
      id,
      { workTimes: formattedWorkTimes },
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

// دالة مساعدة للتحقق من أيام الإجازات
const isVacationDay = (date, vacationDays) => {
  if (!vacationDays || !Array.isArray(vacationDays)) {
    return false;
  }
  
  const year = date.getFullYear();
  const month = date.getMonth() + 1; // 1-12
  const day = date.getDate();
  
  for (const vacation of vacationDays) {
    // التحقق من الإجازة اليومية (التاريخ كاملاً)
    if (vacation) {
      let vacationDate;
      
      // التعامل مع البيانات القديمة والجديدة
      if (typeof vacation === 'string') {
        // البيانات الجديدة - تاريخ كسلسلة نصية
        vacationDate = new Date(vacation);
      } else if (vacation && typeof vacation === 'object' && vacation.date) {
        // البيانات القديمة - كائن مع حقل date
        vacationDate = new Date(vacation.date);
      }
      
      if (vacationDate && !isNaN(vacationDate.getTime())) {
        if (vacationDate.getFullYear() === year && 
            vacationDate.getMonth() + 1 === month && 
            vacationDate.getDate() === day) {
          return true;
        }
      }
    }
  }
  
  return false;
};

// تحديث جدول العمل والإجازات للطبيب
app.put('/doctor/:id/work-schedule', async (req, res) => {
  try {
    const { id } = req.params;
    const { workTimes, vacationDays } = req.body;
    
    // إضافة سجل مفصل للبيانات المستلمة
    console.log('🔍 /doctor/:id/work-schedule - البيانات المستلمة:', {
      id,
      workTimesCount: workTimes ? workTimes.length : 0,
      vacationDaysCount: vacationDays ? vacationDays.length : 0,
      workTimes: workTimes,
      vacationDays: vacationDays
    });
    
    // إضافة سجل مفصل لـ req.body
    console.log('🔍 req.body كاملاً:', req.body);
    console.log('🔍 نوع البيانات المستلمة:', {
      workTimesType: typeof workTimes,
      vacationDaysType: typeof vacationDays,
      workTimesIsArray: Array.isArray(workTimes),
      vacationDaysIsArray: Array.isArray(vacationDays)
    });
    
    // إضافة سجل مفصل للبيانات بعد التصفية
    console.log('🔍 البيانات بعد التصفية:', {
      workTimes: workTimes,
      vacationDays: vacationDays,
      workTimesLength: workTimes ? workTimes.length : 'undefined',
      vacationDaysLength: vacationDays ? vacationDays.length : 'undefined'
    });

    // السماح بمصفوفات فارغة
    if (!Array.isArray(workTimes)) {
      console.error('❌ workTimes ليس مصفوفة:', {
        workTimes,
        type: typeof workTimes,
        isArray: Array.isArray(workTimes)
      });
      return res.status(400).json({ error: 'بيانات أوقات الدوام غير صحيحة' });
    }

    if (!Array.isArray(vacationDays)) {
      console.error('❌ vacationDays ليس مصفوفة:', {
        vacationDays,
        type: typeof vacationDays,
        isArray: Array.isArray(vacationDays)
      });
      return res.status(400).json({ error: 'بيانات أيام الإجازات غير صحيحة' });
    }

    // التحقق من أن أوقات الدوام تحتوي على البيانات المطلوبة إذا لم تكن فارغة
    if (workTimes.length > 0) {
      console.log('🔍 التحقق من صحة أوقات الدوام...');
      workTimes.forEach((wt, index) => {
        console.log(`  WorkTime ${index + 1}:`, {
          day: wt.day,
          from: wt.from,
          to: wt.to,
          start_time: wt.start_time,
          end_time: wt.end_time,
          is_available: wt.is_available,
          dayValid: !!wt.day,
          fromValid: !!wt.from,
          toValid: !!wt.to,
          startTimeValid: !!wt.start_time,
          endTimeValid: !!wt.end_time,
          isAvailableValid: wt.is_available !== undefined
        });
      });
      
      // التحقق من تكرار الأيام
      const days = workTimes.map(wt => wt.day);
      const uniqueDays = [...new Set(days)];
      if (days.length !== uniqueDays.length) {
        console.error('❌ يوجد تكرار في الأيام:', days);
        return res.status(400).json({ error: 'لا يمكن تكرار نفس اليوم أكثر من مرة' });
      }
      
      const invalidWorkTimes = workTimes.filter(wt => 
        !wt || typeof wt !== 'object' || !wt.day || !wt.from || !wt.to
      );
      
      if (invalidWorkTimes.length > 0) {
        console.error('❌ بيانات أوقات الدوام غير صحيحة - الحقول الأساسية مفقودة:', invalidWorkTimes);
        console.error('❌ تفاصيل الأخطاء:');
        invalidWorkTimes.forEach((wt, index) => {
          console.error(`  WorkTime ${index + 1}:`, {
            isObject: typeof wt === 'object',
            hasDay: !!wt?.day,
            hasFrom: !!wt?.from,
            hasTo: !!wt?.to,
            day: wt?.day,
            from: wt?.from,
            to: wt?.to
          });
        });
        return res.status(400).json({ error: 'بيانات أوقات الدوام غير صحيحة - يرجى التأكد من إدخال جميع البيانات المطلوبة' });
      }
      
      // التحقق من أن جميع workTimes تحتوي على الحقول الأساسية فقط
      console.log('✅ جميع workTimes تحتوي على الحقول الأساسية المطلوبة');
      
      // التحقق من أن جميع workTimes تحتوي على الحقول الأساسية
      const hasValidWorkTimes = workTimes.every(wt => 
        wt && typeof wt === 'object' && 
        wt.day && wt.day.trim() !== '' && wt.from && wt.to
      );
      
      if (!hasValidWorkTimes) {
        console.error('❌ بعض أوقات الدوام لا تحتوي على البيانات المطلوبة');
        return res.status(400).json({ error: 'بيانات أوقات الدوام غير صحيحة - يرجى التأكد من إدخال جميع البيانات المطلوبة' });
      }
      
      console.log('✅ جميع أوقات الدوام صحيحة');
    }

    // تنسيق workTimes للشكل البسيط المطلوب في قاعدة البيانات
    const formattedWorkTimes = workTimes.map(wt => {
      // التحقق من صحة البيانات قبل التنسيق
      if (!wt || !wt.day || !wt.from || !wt.to) {
        console.error('❌ بيانات غير صحيحة قبل التنسيق في السيرفر:', wt);
        return null;
      }
      
      // الشكل البسيط: day, from, to فقط
      const formatted = {
        day: wt.day,
        from: wt.from,
        to: wt.to
      };
      
      console.log('✅ تم تنسيق workTime في السيرفر:', formatted);
      return formatted;
    }).filter(Boolean); // إزالة القيم الفارغة

    // التحقق من أن formattedWorkTimes يحتوي على بيانات
    if (!formattedWorkTimes || formattedWorkTimes.length === 0) {
      console.error('❌ formattedWorkTimes فارغ أو غير صحيح في السيرفر');
      return res.status(400).json({ error: 'خطأ في تنسيق البيانات - يرجى المحاولة مرة أخرى' });
    }
    
    console.log('🔍 formattedWorkTimes قبل التحديث:', formattedWorkTimes);
    
    // التحقق النهائي من أن جميع formattedWorkTimes تحتوي على الحقول الأساسية
    const finalValidation = formattedWorkTimes.every(wt => 
      wt && wt.day && wt.from && wt.to
    );
    
    if (!finalValidation) {
      console.error('❌ التحقق النهائي فشل في السيرفر - بعض الكائنات لا تحتوي على الحقول الأساسية');
      console.error('❌ formattedWorkTimes:', formattedWorkTimes);
      return res.status(400).json({ error: 'خطأ في تنسيق البيانات - يرجى المحاولة مرة أخرى' });
    }
    
    console.log('✅ التحقق النهائي نجح في السيرفر - جميع الكائنات تحتوي على الحقول الأساسية');
    
    const doctor = await Doctor.findByIdAndUpdate(
      id,
      { workTimes: formattedWorkTimes, vacationDays },
      { new: true }
    );
    
    console.log('🔍 تم تحديث الطبيب بنجاح');
    
    console.log('🔍 workTimes بعد التنسيق:', formattedWorkTimes);

    if (!doctor) {
      return res.status(404).json({ error: 'لم يتم العثور على الطبيب' });
    }

    const responseData = { 
      message: 'تم تحديث جدول العمل والإجازات بنجاح',
      workTimes: doctor.workTimes,
      vacationDays: doctor.vacationDays
    };
    
    console.log('🔍 البيانات المرسلة في الاستجابة:', responseData);
    
    // التحقق من أن البيانات المرسلة في الاستجابة صحيحة
    if (!responseData.workTimes || !Array.isArray(responseData.workTimes)) {
      console.error('❌ البيانات المرسلة في الاستجابة غير صحيحة:', responseData);
      return res.status(500).json({ error: 'خطأ في البيانات المرسلة' });
    }
    
    // التحقق من أن جميع workTimes في الاستجابة تحتوي على الحقول الأساسية
    const responseValidation = responseData.workTimes.every(wt => 
      wt && wt.day && wt.from && wt.to
    );
    
    if (!responseValidation) {
      console.error('❌ workTimes في الاستجابة غير صحيحة:', responseData.workTimes);
      return res.status(500).json({ error: 'خطأ في البيانات المرسلة' });
    }
    
    console.log('✅ البيانات المرسلة في الاستجابة صحيحة');
    
    res.json(responseData);
  } catch (err) {
    console.error('❌ خطأ في تحديث جدول العمل والإجازات:', err);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث جدول العمل والإجازات' });
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

// ===== ENDPOINTS الإعلانات =====

// جلب الإعلانات حسب الهدف
app.get('/advertisements/:target', async (req, res) => {
  try {
    const { target } = req.params;
    
    let query = { isActive: true };
    
    if (target === 'both') {
      // إعلانات للجميع
      query.target = { $in: ['both', 'users', 'doctors'] };
    } else {
      // إعلانات محددة
      query.target = { $in: [target, 'both'] };
    }
    
    // التحقق من التاريخ
    const now = new Date();
    query.$and = [
      { $or: [{ startDate: { $lte: now } }, { startDate: { $exists: false } }] },
      { $or: [{ endDate: { $gte: now } }, { endDate: { $exists: false } }] }
    ];
    
    // جلب الإعلانات (سنستخدم مصفوفة فارغة مؤقتاً)
    const advertisements = [];
    
    res.json(advertisements);
  } catch (error) {
    console.error('خطأ في جلب الإعلانات:', error);
    res.status(500).json({ error: 'خطأ في جلب الإعلانات' });
  }
});

// إنشاء إعلان جديد
app.post('/advertisements', async (req, res) => {
  try {
    const { title, description, image, target, link, startDate, endDate, isActive } = req.body;
    
    // التحقق من الحقول المطلوبة
    if (!title || !description || !image) {
      return res.status(400).json({ error: 'العنوان والوصف والصورة مطلوبة' });
    }
    
    // إنشاء الإعلان (سنستخدم كائن بسيط مؤقتاً)
    const advertisement = {
      _id: Date.now().toString(),
      title,
      description,
      image,
      target: target || 'users',
      link: link || '',
      startDate: startDate || new Date(),
      endDate: endDate || null,
      isActive: isActive !== false,
      stats: { views: 0, clicks: 0 },
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    res.status(201).json(advertisement);
  } catch (error) {
    console.error('خطأ في إنشاء الإعلان:', error);
    res.status(500).json({ error: 'خطأ في إنشاء الإعلان' });
  }
});

// تحديث إعلان
app.put('/advertisements/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    // تحديث الإعلان (سنستخدم كائن بسيط مؤقتاً)
    const advertisement = {
      ...updateData,
      _id: id,
      updatedAt: new Date()
    };
    
    res.json(advertisement);
  } catch (error) {
    console.error('خطأ في تحديث الإعلان:', error);
    res.status(500).json({ error: 'خطأ في تحديث الإعلان' });
  }
});

// حذف إعلان
app.delete('/advertisements/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // حذف الإعلان (سنستخدم رسالة نجاح مؤقتاً)
    res.json({ message: 'تم حذف الإعلان بنجاح' });
  } catch (error) {
    console.error('خطأ في حذف الإعلان:', error);
    res.status(500).json({ error: 'خطأ في حذف الإعلان' });
  }
});

// تحديث إحصائيات الإعلان
app.post('/advertisements/:id/stats', async (req, res) => {
  try {
    const { id } = req.params;
    const { action } = req.body;
    
    // تحديث الإحصائيات (سنستخدم رسالة نجاح مؤقتاً)
    res.json({ success: true, message: 'تم تحديث الإحصائيات بنجاح' });
  } catch (error) {
    console.error('خطأ في تحديث الإحصائيات:', error);
    res.status(500).json({ error: 'خطأ في تحديث الإحصائيات' });
  }
});

// ===== نهاية endpoints الإعلانات =====

// ===== نظام إدارة الموظفين للأطباء =====

// إضافة موظف جديد للطبيب
app.post('/api/employees', async (req, res) => {
  try {
    const { doctorId, phone, name, email, position, salary, commission, notes } = req.body;
    
    // التحقق من الحقول المطلوبة
    if (!doctorId || !phone || !name) {
      return res.status(400).json({ error: 'معرف الطبيب ورقم الهاتف والاسم مطلوبة' });
    }
    
    // التحقق من أن الطبيب موجود
    const doctor = await Doctor.findById(doctorId);
    if (!doctor) {
      return res.status(404).json({ error: 'الطبيب غير موجود' });
    }
    
    // التحقق من أن رقم الهاتف صحيح (تنسيق عراقي)
    const iraqPhoneRegex = /^(\+964|964|0)?7[0-9]{8}$/;
    if (!iraqPhoneRegex.test(phone)) {
      return res.status(400).json({ error: 'رقم الهاتف يجب أن يكون بتنسيق عراقي صحيح' });
    }
    
    // إنشاء الموظف
    const employee = new Employee({
      doctorId,
      phone,
      name,
      email,
      position: position || 'موظف',
      salary,
      commission: commission || 0,
      notes
    });
    
    await employee.save();
    
    res.status(201).json({
      success: true,
      message: 'تم إضافة الموظف بنجاح',
      employee
    });
    
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'هذا الموظف موجود بالفعل لهذا الطبيب' });
    }
    console.error('خطأ في إضافة الموظف:', error);
    res.status(500).json({ error: 'خطأ في إضافة الموظف' });
  }
});

// جلب جميع موظفي الطبيب
app.get('/api/employees/:doctorId', async (req, res) => {
  try {
    const { doctorId } = req.params;
    
    const employees = await Employee.find({ doctorId, status: 'active' })
      .populate('userId', 'first_name email')
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      employees
    });
    
  } catch (error) {
    console.error('خطأ في جلب الموظفين:', error);
    res.status(500).json({ error: 'خطأ في جلب الموظفين' });
  }
});

// تحديث بيانات الموظف
app.put('/api/employees/:employeeId', async (req, res) => {
  try {
    const { employeeId } = req.params;
    const updateData = req.body;
    
    // إزالة الحقول التي لا يمكن تحديثها
    delete updateData.doctorId;
    delete updateData.createdAt;
    
    const employee = await Employee.findByIdAndUpdate(
      employeeId,
      { ...updateData, updatedAt: new Date() },
      { new: true }
    );
    
    if (!employee) {
      return res.status(404).json({ error: 'الموظف غير موجود' });
    }
    
    res.json({
      success: true,
      message: 'تم تحديث بيانات الموظف بنجاح',
      employee
    });
    
  } catch (error) {
    console.error('خطأ في تحديث الموظف:', error);
    res.status(500).json({ error: 'خطأ في تحديث الموظف' });
  }
});

// حذف موظف
app.delete('/api/employees/:employeeId', async (req, res) => {
  try {
    const { employeeId } = req.params;
    
    const employee = await Employee.findByIdAndDelete(employeeId);
    
    if (!employee) {
      return res.status(404).json({ error: 'الموظف غير موجود' });
    }
    
    // حذف جميع النقاط المرتبطة بالموظف
    await Points.deleteMany({ employeeId });
    
    // حذف الإحصائيات المرتبطة بالموظف
    await EmployeeStats.deleteMany({ employeeId });
    
    res.json({
      success: true,
      message: 'تم حذف الموظف وجميع بياناته بنجاح'
    });
    
  } catch (error) {
    console.error('خطأ في حذف الموظف:', error);
    res.status(500).json({ error: 'خطأ في حذف الموظف' });
  }
});

// إضافة نقاط للموظف
app.post('/api/employees/:employeeId/points', async (req, res) => {
  try {
    const { employeeId } = req.params;
    const { points, type, description, appointmentId } = req.body;
    
    // التحقق من الحقول المطلوبة
    if (!points || !type) {
      return res.status(400).json({ error: 'عدد النقاط ونوعها مطلوبة' });
    }
    
    // التحقق من أن الموظف موجود
    const employee = await Employee.findById(employeeId);
    if (!employee) {
      return res.status(404).json({ error: 'الموظف غير موجود' });
    }
    
    // حساب الأسبوع والشهر والسنة
    const now = new Date();
    const week = Math.ceil((now.getDate() + new Date(now.getFullYear(), now.getMonth(), 1).getDay()) / 7);
    const month = now.getMonth() + 1;
    const year = now.getFullYear();
    
    // إنشاء النقاط
    const pointsRecord = new Points({
      employeeId,
      doctorId: employee.doctorId,
      appointmentId,
      points,
      type,
      description,
      week,
      month,
      year
    });
    
    await pointsRecord.save();
    
    // تحديث الإحصائيات
    await updateEmployeeStats(employeeId, employee.doctorId);
    
    res.status(201).json({
      success: true,
      message: 'تم إضافة النقاط بنجاح',
      points: pointsRecord
    });
    
  } catch (error) {
    console.error('خطأ في إضافة النقاط:', error);
    res.status(500).json({ error: 'خطأ في إضافة النقاط' });
  }
});

// جلب نقاط الموظف
app.get('/api/employees/:employeeId/points', async (req, res) => {
  try {
    const { employeeId } = req.params;
    const { period, startDate, endDate } = req.query;
    
    let query = { employeeId };
    
    // فلترة حسب الفترة
    if (period === 'weekly') {
      const now = new Date();
      const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay());
      const weekEnd = new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
      query.date = { $gte: weekStart, $lt: weekEnd };
    } else if (period === 'monthly') {
      const now = new Date();
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
      const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);
      query.date = { $gte: monthStart, $lt: monthEnd };
    } else if (period === 'yearly') {
      const now = new Date();
      const yearStart = new Date(now.getFullYear(), 0, 1);
      const yearEnd = new Date(now.getFullYear() + 1, 0, 1);
      query.date = { $gte: yearStart, $lt: yearEnd };
    } else if (startDate && endDate) {
      query.date = { $gte: new Date(startDate), $lte: new Date(endDate) };
    }
    
    const points = await Points.find(query)
      .populate('appointmentId', 'date time userName patientName')
      .sort({ date: -1 });
    
    // حساب الإجمالي
    const totalPoints = points.reduce((sum, p) => sum + p.points, 0);
    
    res.json({
      success: true,
      points,
      totalPoints,
      count: points.length
    });
    
  } catch (error) {
    console.error('خطأ في جلب النقاط:', error);
    res.status(500).json({ error: 'خطأ في جلب النقاط' });
  }
});

// جلب إحصائيات الموظف
app.get('/api/employees/:employeeId/stats', async (req, res) => {
  try {
    const { employeeId } = req.params;
    const { period } = req.query;
    
    let stats;
    
    if (period) {
      stats = await EmployeeStats.findOne({ 
        employeeId, 
        period 
      }).sort({ lastUpdated: -1 });
    } else {
      // جلب جميع الإحصائيات
      stats = await EmployeeStats.find({ employeeId })
        .sort({ period: 1, lastUpdated: -1 });
    }
    
    if (!stats || stats.length === 0) {
      // إنشاء إحصائيات جديدة إذا لم تكن موجودة
      await updateEmployeeStats(employeeId);
      stats = await EmployeeStats.find({ employeeId })
        .sort({ period: 1, lastUpdated: -1 });
    }
    
    res.json({
      success: true,
      stats
    });
    
  } catch (error) {
    console.error('خطأ في جلب الإحصائيات:', error);
    res.status(500).json({ error: 'خطأ في جلب الإحصائيات' });
  }
});

// ربط موظف بمستخدم موجود (عن طريق رقم الهاتف)
app.post('/api/employees/:employeeId/link-user', async (req, res) => {
  try {
    const { employeeId } = req.params;
    const { phone } = req.body;
    
    if (!phone) {
      return res.status(400).json({ error: 'رقم الهاتف مطلوب' });
    }
    
    // البحث عن المستخدم برقم الهاتف
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(404).json({ error: 'لم يتم العثور على مستخدم بهذا الرقم' });
    }
    
    // تحديث الموظف
    const employee = await Employee.findByIdAndUpdate(
      employeeId,
      { userId: user._id },
      { new: true }
    );
    
    if (!employee) {
      return res.status(404).json({ error: 'الموظف غير موجود' });
    }
    
    res.json({
      success: true,
      message: 'تم ربط الموظف بالمستخدم بنجاح',
      employee
    });
    
  } catch (error) {
    console.error('خطأ في ربط الموظف:', error);
    res.status(500).json({ error: 'خطأ في ربط الموظف' });
  }
});

// البحث عن موظف برقم الهاتف
app.get('/api/employees/search/:phone', async (req, res) => {
  try {
    const { phone } = req.params;
    const { doctorId } = req.query;
    
    if (!phone) {
      return res.status(400).json({ error: 'رقم الهاتف مطلوب' });
    }
    
    let query = { phone };
    if (doctorId) {
      query.doctorId = doctorId;
    }
    
    const employee = await Employee.findOne(query)
      .populate('userId', 'first_name email')
      .populate('doctorId', 'name specialty');
    
    if (!employee) {
      return res.status(404).json({ error: 'لم يتم العثور على موظف بهذا الرقم' });
    }
    
    res.json({
      success: true,
      employee
    });
    
  } catch (error) {
    console.error('خطأ في البحث عن الموظف:', error);
    res.status(500).json({ error: 'خطأ في البحث عن الموظف' });
  }
});

// جلب إحصائيات موظفين الطبيب
app.get('/api/doctors/:doctorId/employees-stats', async (req, res) => {
  try {
    const { doctorId } = req.params;
    const { period } = req.query;
    
    // جلب جميع موظفي الطبيب
    const employees = await Employee.find({ doctorId, status: 'active' });
    
    if (employees.length === 0) {
      return res.json({
        success: true,
        employees: [],
        totalStats: {
          totalEmployees: 0,
          totalPoints: 0,
          totalAppointments: 0,
          averagePoints: 0
        }
      });
    }
    
    // جلب إحصائيات كل موظف
    const employeesWithStats = await Promise.all(
      employees.map(async (employee) => {
        let stats;
        if (period) {
          stats = await EmployeeStats.findOne({ 
            employeeId: employee._id, 
            period 
          });
        } else {
          // جلب الإحصائيات الأسبوعية كافتراضي
          stats = await EmployeeStats.findOne({ 
            employeeId: employee._id, 
            period: 'weekly' 
          });
        }
        
        return {
          ...employee.toObject(),
          stats: stats || {
            totalAppointments: 0,
            attendedAppointments: 0,
            totalPoints: 0,
            averagePoints: 0
          }
        };
      })
    );
    
    // حساب الإحصائيات الإجمالية
    const totalStats = employeesWithStats.reduce((acc, emp) => {
      acc.totalPoints += emp.stats.totalPoints || 0;
      acc.totalAppointments += emp.stats.totalAppointments || 0;
      return acc;
    }, { totalPoints: 0, totalAppointments: 0 });
    
    totalStats.totalEmployees = employeesWithStats.length;
    totalStats.averagePoints = totalStats.totalEmployees > 0 
      ? Math.round((totalStats.totalPoints / totalStats.totalEmployees) * 100) / 100 
      : 0;
    
    res.json({
      success: true,
      employees: employeesWithStats,
      totalStats
    });
    
  } catch (error) {
    console.error('خطأ في جلب إحصائيات الموظفين:', error);
    res.status(500).json({ error: 'خطأ في جلب إحصائيات الموظفين' });
  }
});

// دالة تحديث إحصائيات الموظف
async function updateEmployeeStats(employeeId, doctorId = null) {
  try {
    if (!doctorId) {
      const employee = await Employee.findById(employeeId);
      if (!employee) return;
      doctorId = employee.doctorId;
    }
    
    const now = new Date();
    
    // تحديث الإحصائيات الأسبوعية
    const weekStart = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay());
    const weekEnd = new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
    
    const weeklyStats = await calculateEmployeeStats(employeeId, doctorId, 'weekly', weekStart, weekEnd);
    await EmployeeStats.findOneAndUpdate(
      { employeeId, period: 'weekly' },
      weeklyStats,
      { upsert: true, new: true }
    );
    
    // تحديث الإحصائيات الشهرية
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    
    const monthlyStats = await calculateEmployeeStats(employeeId, doctorId, 'monthly', monthStart, monthEnd);
    await EmployeeStats.findOneAndUpdate(
      { employeeId, period: 'monthly' },
      monthlyStats,
      { upsert: true, new: true }
    );
    
    // تحديث الإحصائيات السنوية
    const yearStart = new Date(now.getFullYear(), 0, 1);
    const yearEnd = new Date(now.getFullYear() + 1, 0, 1);
    
    const yearlyStats = await calculateEmployeeStats(employeeId, doctorId, 'yearly', yearStart, yearEnd);
    await EmployeeStats.findOneAndUpdate(
      { employeeId, period: 'yearly' },
      yearlyStats,
      { upsert: true, new: true }
    );
    
  } catch (error) {
    console.error('خطأ في تحديث إحصائيات الموظف:', error);
  }
}

// دالة حساب إحصائيات الموظف
async function calculateEmployeeStats(employeeId, doctorId, period, startDate, endDate) {
  try {
    // جلب النقاط في الفترة المحددة
    const points = await Points.find({
      employeeId,
      date: { $gte: startDate, $lt: endDate }
    });
    
    // جلب المواعيد المرتبطة
    const appointments = await Appointment.find({
      doctorId,
      date: { $gte: startDate.toISOString().split('T')[0], $lt: endDate.toISOString().split('T')[0] }
    });
    
    const totalPoints = points.reduce((sum, p) => sum + p.points, 0);
    const totalAppointments = appointments.length;
    const attendedAppointments = appointments.filter(a => a.attendance === 'present').length;
    const averagePoints = totalPoints / Math.max(totalAppointments, 1);
    
    return {
      employeeId,
      doctorId,
      period,
      startDate,
      endDate,
      totalAppointments,
      attendedAppointments,
      totalPoints,
      averagePoints: Math.round(averagePoints * 100) / 100,
      lastUpdated: new Date()
    };
    
  } catch (error) {
    console.error('خطأ في حساب الإحصائيات:', error);
    return null;
  }
}

// ===== نهاية نظام إدارة الموظفين =====

// إضافة موعد خاص (special appointment)

// ===== 404 Handler - يجب أن يكون في النهاية =====
app.use('*', (req, res) => {
  console.log('🚫 404 - Endpoint not found:', req.method, req.originalUrl);
  res.status(404).json({ 
    error: 'Endpoint not found',
    message: 'The requested endpoint does not exist',
    path: req.originalUrl,
    method: req.method
  });
});