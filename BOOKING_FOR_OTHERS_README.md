# ميزة الحجز لشخص آخر - TabibiQ Backend

## 📋 نظرة عامة
تم إضافة ميزة الحجز لشخص آخر إلى نظام TabibiQ، مما يسمح للمستخدمين بحجز مواعيد للأطباء نيابة عن أشخاص آخرين (أفراد العائلة، الأصدقاء، إلخ).

## 🆕 الميزات الجديدة

### 1. نموذج الحجوزات المحدث
تم تحديث نموذج `Appointment` ليشمل:
- `patientName`: اسم المريض (قد يكون مختلف عن اسم المستخدم)
- `patientPhone`: رقم هاتف المريض
- `isBookingForOther`: مؤشر إذا كان الحجز لشخص آخر
- `bookerName`: اسم الشخص الذي قام بالحجز

### 2. مسارات API الجديدة

#### أ) الحجز لشخص آخر
```
POST /appointments-for-other
```
**المعاملات المطلوبة:**
- `userId`: معرف المستخدم الذي يقوم بالحجز
- `doctorId`: معرف الطبيب
- `userName`: اسم المستخدم
- `doctorName`: اسم الطبيب
- `date`: تاريخ الموعد
- `time`: وقت الموعد
- `reason`: سبب الزيارة
- `patientAge`: عمر المريض
- `patientName`: اسم المريض (مطلوب)
- `patientPhone`: رقم هاتف المريض
- `bookerName`: اسم الشخص الذي قام بالحجز
- `duration`: مدة الموعد (اختياري)

**مثال للاستخدام:**
```json
{
  "userId": "user123",
  "doctorId": "doctor456",
  "userName": "أحمد محمد",
  "doctorName": "د. علي حسن",
  "date": "2024-01-15",
  "time": "10:00",
  "reason": "فحص دوري",
  "patientAge": 25,
  "patientName": "فاطمة أحمد",
  "patientPhone": "+964771234567",
  "bookerName": "أحمد محمد",
  "duration": 30
}
```

#### ب) تفاصيل الموعد
```
GET /appointment-details/:appointmentId
```
**الاستجابة:**
```json
{
  "success": true,
  "appointment": {
    "appointmentId": "app123",
    "date": "2024-01-15",
    "time": "10:00",
    "doctorName": "د. علي حسن",
    "doctorSpecialty": "طب القلب",
    "reason": "فحص دوري",
    "status": "pending",
    "duration": 30,
    "isBookingForOther": true,
    "patientInfo": {
      "name": "فاطمة أحمد",
      "age": 25,
      "phone": "+964771234567"
    },
    "bookerInfo": {
      "name": "أحمد محمد",
      "phone": "+964778765432"
    },
    "message": "الحجز من قبل: أحمد محمد للمريض: فاطمة أحمد"
  }
}
```

#### ج) إحصائيات المواعيد
```
GET /appointments-stats/:doctorId
```
**الاستجابة:**
```json
{
  "success": true,
  "stats": {
    "total": 150,
    "forOthers": 45,
    "selfBookings": 105,
    "statusBreakdown": [
      { "_id": "pending", "count": 30 },
      { "_id": "confirmed", "count": 100 },
      { "_id": "completed", "count": 20 }
    ],
    "recentBookings": 25,
    "percentageForOthers": 30
  }
}
```

### 3. تحديث المسارات الموجودة

#### أ) مسار الحجز العادي
```
POST /appointments
```
يدعم الآن الحجز لشخص آخر مع المعاملات الإضافية.

#### ب) عرض مواعيد الطبيب
```
GET /doctor-appointments/:doctorId
```
يعرض الآن معلومات إضافية للحجز لشخص آخر في حقل `displayInfo`.

#### ج) إلغاء الموعد
```
DELETE /appointments/:id
```
يعرض رسائل مختلفة للحجز العادي والحجز لشخص آخر.

## 🔧 كيفية الاستخدام

### 1. الحجز لشخص آخر
```javascript
const response = await fetch('/appointments-for-other', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    userId: 'user123',
    doctorId: 'doctor456',
    userName: 'أحمد محمد',
    doctorName: 'د. علي حسن',
    date: '2024-01-15',
    time: '10:00',
    reason: 'فحص دوري',
    patientAge: 25,
    patientName: 'فاطمة أحمد',
    patientPhone: '+964771234567',
    bookerName: 'أحمد محمد',
    duration: 30
  })
});
```

### 2. عرض تفاصيل الموعد
```javascript
const response = await fetch(`/appointment-details/${appointmentId}`);
const data = await response.json();
console.log(data.appointment.message);
```

### 3. عرض إحصائيات الطبيب
```javascript
const response = await fetch(`/appointments-stats/${doctorId}`);
const data = await response.json();
console.log(`نسبة الحجز لشخص آخر: ${data.stats.percentageForOthers}%`);
```

## 📱 عرض المعلومات للدكتور

عند عرض المواعيد للدكتور، ستظهر المعلومات التالية:

### للحجز العادي:
- اسم المريض: اسم المستخدم
- رقم الهاتف: رقم المستخدم
- رسالة: "الحجز من قبل: [اسم المستخدم]"

### للحجز لشخص آخر:
- اسم المريض: اسم المريض المحدد
- رقم الهاتف: رقم المريض
- رسالة: "الحجز من قبل: [اسم الحاجز] للمريض: [اسم المريض]"

## 🚀 المزايا

1. **مرونة في الحجز**: يمكن للمستخدمين حجز مواعيد لأفراد العائلة والأصدقاء
2. **معلومات واضحة**: يرى الطبيب بوضوح من هو المريض ومن قام بالحجز
3. **إحصائيات مفصلة**: يمكن للطبيب رؤية نسبة الحجز لشخص آخر
4. **تتبع أفضل**: تتبع منفصل للمرضى والحاجزين
5. **رسائل مخصصة**: رسائل مختلفة حسب نوع الحجز

## 🔒 الأمان

- التحقق من صحة البيانات المدخلة
- التحقق من عدم وجود مواعيد مكررة
- التحقق من أيام الإجازات
- تسجيل جميع العمليات في السجلات

## 📝 ملاحظات

- يجب أن يكون عمر المريض بين 1 و 120 سنة
- اسم المريض مطلوب عند الحجز لشخص آخر
- يتم حفظ معلومات الحاجز والمريض بشكل منفصل
- يمكن إلغاء الموعد في أي وقت
