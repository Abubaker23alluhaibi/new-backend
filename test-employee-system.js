const axios = require('axios');

// تكوين الاختبار
const BASE_URL = 'http://localhost:5000/api';
const TEST_DOCTOR_ID = 'test_doctor_id'; // استبدل بمعرف طبيب حقيقي للاختبار

// بيانات اختبار الموظف
const testEmployee = {
  doctorId: TEST_DOCTOR_ID,
  name: 'أحمد محمد',
  phone: '07801234567',
  email: 'ahmed@test.com',
  position: 'ممرض',
  salary: '500000',
  commission: '10',
  notes: 'موظف اختبار'
};

async function testEmployeeSystem() {
  console.log('🚀 بدء اختبار نظام إدارة الموظفين...\n');

  try {
    // 1. اختبار إضافة موظف جديد
    console.log('1️⃣ اختبار إضافة موظف جديد...');
    const addResponse = await axios.post(`${BASE_URL}/employees`, testEmployee);
    console.log('✅ تم إضافة الموظف بنجاح:', addResponse.data.name);
    
    const employeeId = addResponse.data._id;

    // 2. اختبار جلب الموظفين
    console.log('\n2️⃣ اختبار جلب الموظفين...');
    const getResponse = await axios.get(`${BASE_URL}/employees/${TEST_DOCTOR_ID}`);
    console.log('✅ تم جلب الموظفين بنجاح. عدد الموظفين:', getResponse.data.length);

    // 3. اختبار البحث عن موظف
    console.log('\n3️⃣ اختبار البحث عن موظف...');
    const searchResponse = await axios.get(`${BASE_URL}/employees/search?doctorId=${TEST_DOCTOR_ID}&query=أحمد`);
    console.log('✅ تم البحث بنجاح. نتائج البحث:', searchResponse.data.length);

    // 4. اختبار جلب إحصائيات الموظف
    console.log('\n4️⃣ اختبار جلب إحصائيات الموظف...');
    const statsResponse = await axios.get(`${BASE_URL}/employees/${employeeId}/stats?period=weekly`);
    console.log('✅ تم جلب الإحصائيات بنجاح:', statsResponse.data);

    // 5. اختبار حذف الموظف
    console.log('\n5️⃣ اختبار حذف الموظف...');
    const deleteResponse = await axios.delete(`${BASE_URL}/employees/${employeeId}`);
    console.log('✅ تم حذف الموظف بنجاح');

    // 6. التحقق من الحذف
    console.log('\n6️⃣ التحقق من الحذف...');
    const verifyResponse = await axios.get(`${BASE_URL}/employees/${TEST_DOCTOR_ID}`);
    const remainingEmployees = verifyResponse.data.filter(emp => emp._id === employeeId);
    if (remainingEmployees.length === 0) {
      console.log('✅ تم حذف الموظف بنجاح');
    } else {
      console.log('❌ فشل في حذف الموظف');
    }

    console.log('\n🎉 تم اختبار جميع الوظائف بنجاح!');

  } catch (error) {
    console.error('\n❌ حدث خطأ أثناء الاختبار:', error.response?.data || error.message);
    
    if (error.response?.status === 404) {
      console.log('💡 تأكد من أن الخادم يعمل على المنفذ 5000');
    }
    
    if (error.response?.status === 500) {
      console.log('💡 تأكد من أن قاعدة البيانات متصلة وأن النماذج تم إنشاؤها');
    }
  }
}

// اختبار إضافة نقاط للموظف
async function testPointsSystem() {
  console.log('\n🔢 اختبار نظام النقاط...\n');

  try {
    // إضافة موظف جديد للاختبار
    const addResponse = await axios.post(`${BASE_URL}/employees`, testEmployee);
    const employeeId = addResponse.data._id;
    console.log('✅ تم إضافة موظف للاختبار:', addResponse.data.name);

    // اختبار إضافة نقاط
    console.log('\n1️⃣ اختبار إضافة نقاط للموظف...');
    const pointsData = {
      employeeId: employeeId,
      points: 10,
      reason: 'اختبار نظام النقاط',
      date: new Date().toISOString()
    };

    const pointsResponse = await axios.post(`${BASE_URL}/employees/${employeeId}/points`, pointsData);
    console.log('✅ تم إضافة النقاط بنجاح:', pointsResponse.data);

    // اختبار جلب النقاط
    console.log('\n2️⃣ اختبار جلب نقاط الموظف...');
    const getPointsResponse = await axios.get(`${BASE_URL}/employees/${employeeId}/points`);
    console.log('✅ تم جلب النقاط بنجاح. عدد النقاط:', getPointsResponse.data.length);

    // اختبار حذف الموظف
    await axios.delete(`${BASE_URL}/employees/${employeeId}`);
    console.log('✅ تم تنظيف بيانات الاختبار');

    console.log('\n🎉 تم اختبار نظام النقاط بنجاح!');

  } catch (error) {
    console.error('\n❌ حدث خطأ أثناء اختبار النقاط:', error.response?.data || error.message);
  }
}

// تشغيل الاختبارات
async function runAllTests() {
  console.log('🧪 بدء اختبارات نظام إدارة الموظفين\n');
  console.log('=' .repeat(50));
  
  await testEmployeeSystem();
  await testPointsSystem();
  
  console.log('\n' + '=' .repeat(50));
  console.log('🏁 انتهت جميع الاختبارات');
}

// تشغيل الاختبارات إذا تم استدعاء الملف مباشرة
if (require.main === module) {
  runAllTests().catch(console.error);
}

module.exports = {
  testEmployeeSystem,
  testPointsSystem,
  runAllTests
};
