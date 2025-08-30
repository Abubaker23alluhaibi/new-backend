# نظام إدارة الموظفين للأطباء - TabibiQ

## نظرة عامة
نظام إدارة الموظفين للأطباء يتيح للأطباء إدارة موظفيهم وتتبع أدائهم من خلال نظام نقاط متكامل. النظام يحسب النقاط تلقائياً بناءً على المواعيد المؤكدة والحضور.

## الميزات الرئيسية

### 1. إدارة الموظفين
- إضافة موظفين جدد للطبيب
- تحديث بيانات الموظفين
- حذف الموظفين
- ربط الموظفين بمستخدمين موجودين

### 2. نظام النقاط
- **3 نقاط** لكل موعد مؤكد
- **2 نقاط إضافية** عند حضور المريض
- نقاط مخصصة (مكافآت/خصومات)
- تتبع النقاط أسبوعياً وشهرياً وسنوياً

### 3. الإحصائيات والتقارير
- إحصائيات أسبوعية
- إحصائيات شهرية  
- إحصائيات سنوية
- تقارير الأداء التفصيلية

## النماذج (Models)

### Employee (الموظف)
```javascript
{
  doctorId: ObjectId,        // معرف الطبيب
  userId: ObjectId,          // معرف المستخدم (اختياري)
  phone: String,             // رقم الهاتف العراقي
  name: String,              // اسم الموظف
  email: String,             // البريد الإلكتروني
  position: String,          // المنصب
  status: String,            // الحالة (active/inactive/suspended)
  hireDate: Date,            // تاريخ التعيين
  salary: Number,            // الراتب
  commission: Number,        // العمولة
  notes: String,             // ملاحظات
  createdAt: Date            // تاريخ الإنشاء
}
```

### Points (النقاط)
```javascript
{
  employeeId: ObjectId,      // معرف الموظف
  doctorId: ObjectId,        // معرف الطبيب
  appointmentId: ObjectId,   // معرف الموعد
  points: Number,            // عدد النقاط
  type: String,              // نوع النقاط
  description: String,       // وصف النقاط
  date: Date,                // تاريخ النقاط
  week: Number,              // رقم الأسبوع
  month: Number,             // رقم الشهر
  year: Number               // السنة
}
```

### EmployeeStats (إحصائيات الموظف)
```javascript
{
  employeeId: ObjectId,      // معرف الموظف
  doctorId: ObjectId,        // معرف الطبيب
  period: String,            // الفترة (weekly/monthly/yearly)
  startDate: Date,           // تاريخ البداية
  endDate: Date,             // تاريخ النهاية
  totalAppointments: Number, // إجمالي المواعيد
  attendedAppointments: Number, // المواعيد الحاضرة
  totalPoints: Number,       // إجمالي النقاط
  averagePoints: Number,     // متوسط النقاط
  lastUpdated: Date          // آخر تحديث
}
```

## API Endpoints

### إدارة الموظفين

#### إضافة موظف جديد
```http
POST /api/employees
Content-Type: application/json

{
  "doctorId": "64f1a2b3c4d5e6f7g8h9i0j1",
  "phone": "07801234567",
  "name": "أحمد محمد",
  "email": "ahmed@example.com",
  "position": "سكرتير",
  "salary": 500000,
  "commission": 10,
  "notes": "موظف جديد"
}
```

#### جلب موظفي الطبيب
```http
GET /api/employees/:doctorId
```

#### تحديث بيانات الموظف
```http
PUT /api/employees/:employeeId
Content-Type: application/json

{
  "name": "أحمد محمد علي",
  "salary": 550000,
  "commission": 15
}
```

#### حذف موظف
```http
DELETE /api/employees/:employeeId
```

### نظام النقاط

#### إضافة نقاط للموظف
```http
POST /api/employees/:employeeId/points
Content-Type: application/json

{
  "points": 5,
  "type": "bonus",
  "description": "مكافأة أداء ممتاز",
  "appointmentId": "64f1a2b3c4d5e6f7g8h9i0j2"
}
```

#### جلب نقاط الموظف
```http
GET /api/employees/:employeeId/points?period=weekly
GET /api/employees/:employeeId/points?period=monthly
GET /api/employees/:employeeId/points?period=yearly
GET /api/employees/:employeeId/points?startDate=2024-01-01&endDate=2024-01-31
```

#### جلب إحصائيات الموظف
```http
GET /api/employees/:employeeId/stats?period=weekly
GET /api/employees/:employeeId/stats?period=monthly
GET /api/employees/:employeeId/stats?period=yearly
```

### البحث والربط

#### البحث عن موظف برقم الهاتف
```http
GET /api/employees/search/07801234567?doctorId=64f1a2b3c4d5e6f7g8h9i0j1
```

#### ربط موظف بمستخدم موجود
```http
POST /api/employees/:employeeId/link-user
Content-Type: application/json

{
  "phone": "07801234567"
}
```

#### جلب إحصائيات موظفي الطبيب
```http
GET /api/doctors/:doctorId/employees-stats?period=weekly
```

### تحديث المواعيد مع النقاط

#### تأكيد موعد (إضافة 3 نقاط)
```http
PUT /api/appointments/:id/status
Content-Type: application/json

{
  "status": "confirmed",
  "employeeId": "64f1a2b3c4d5e6f7g8h9i0j3"
}
```

#### تسجيل حضور (إضافة 2 نقاط)
```http
PUT /api/appointments/:id/attendance
Content-Type: application/json

{
  "attendance": "present",
  "employeeId": "64f1a2b3c4d5e6f7g8h9i0j3"
}
```

## نظام النقاط التلقائي

### النقاط التلقائية
1. **موعد مؤكد**: 3 نقاط
2. **حضور المريض**: 2 نقاط إضافية
3. **إجمالي النقاط للموعد**: 5 نقاط (3 + 2)

### حساب النقاط
- يتم حساب النقاط تلقائياً عند تحديث حالة الموعد
- يتم تحديث الإحصائيات فوراً
- يمكن إضافة نقاط مخصصة يدوياً

## التحقق من صحة البيانات

### رقم الهاتف العراقي
يجب أن يكون رقم الهاتف بتنسيق عراقي صحيح:
- `07801234567` (بدون كود البلد)
- `+9647801234567` (مع كود البلد)
- `9647801234567` (مع كود البلد بدون +)

### الفهارس الفريدة
- `{ doctorId: 1, phone: 1 }` - لا يمكن تكرار نفس الرقم لنفس الطبيب

## الأمان والصلاحيات

### التحقق من الملكية
- الطبيب يمكنه إدارة موظفيه فقط
- لا يمكن الوصول لبيانات موظفين أطباء آخرين
- التحقق من صحة معرفات الطبيب والموظف

### معالجة الأخطاء
- رسائل خطأ واضحة باللغة العربية
- تسجيل الأخطاء في السجلات
- عدم توقف العملية عند فشل إضافة النقاط

## أمثلة الاستخدام

### سيناريو كامل لإضافة موظف
1. إضافة موظف جديد
2. ربطه بمستخدم موجود (اختياري)
3. تأكيد مواعيد (إضافة 3 نقاط تلقائياً)
4. تسجيل الحضور (إضافة 2 نقاط تلقائياً)
5. مراجعة الإحصائيات

### مثال على الاستجابة
```json
{
  "success": true,
  "message": "تم إضافة الموظف بنجاح",
  "employee": {
    "_id": "64f1a2b3c4d5e6f7g8h9i0j4",
    "doctorId": "64f1a2b3c4d5e6f7g8h9i0j1",
    "phone": "07801234567",
    "name": "أحمد محمد",
    "position": "سكرتير",
    "status": "active",
    "createdAt": "2024-01-15T10:30:00.000Z"
  }
}
```

## ملاحظات مهمة

1. **الأداء**: يتم تحديث الإحصائيات بشكل متزامن مع إضافة النقاط
2. **النسخ الاحتياطي**: جميع البيانات محفوظة في قاعدة البيانات
3. **التوسع**: يمكن إضافة أنواع نقاط جديدة بسهولة
4. **التقارير**: يمكن إنشاء تقارير مخصصة بناءً على البيانات المخزنة

## الدعم والمساعدة

لأي استفسارات أو مشاكل تقنية، يرجى التواصل مع فريق التطوير.
