const ar = {
  'MikroCloud ISP Manager':'مايكرو كلاود لإدارة شركات الإنترنت','Sign in':'تسجيل الدخول','Email or username':'البريد أو اسم المستخدم',
  'Password':'كلمة المرور','Remember me':'تذكرني','Show':'إظهار','Hide':'إخفاء','Forgot password?':'نسيت كلمة المرور؟',
  'Logout':'خروج','Dashboard':'لوحة التحكم','Companies':'العملاء','Customers':'المشتركون','Employees':'الموظفون','Settings':'الإعدادات',
  'Account':'حسابي','Audit log':'سجل النشاط','Save':'حفظ','Cancel':'إلغاء','Delete':'حذف','Edit':'تعديل','View':'عرض','Add':'إضافة',
  'Search':'بحث','Name':'الاسم','Status':'الحالة','Phone':'الهاتف','Email':'البريد','Actions':'إجراءات','Active':'نشط','Suspended':'موقوف',
  'Trial':'تجريبي','Expired':'منتهي','Suspend':'إيقاف','Activate':'تفعيل','Extend':'تمديد','Days':'أيام','Plan':'الباقة',
  'Total companies':'إجمالي العملاء','Active companies':'عملاء نشطون','Trial companies':'عملاء تجريبيون','Suspended companies':'عملاء موقوفون',
  'Expired subscriptions':'اشتراكات منتهية','Total customers':'إجمالي المشتركين','Recent activity':'آخر النشاط','New company':'عميل جديد',
  'Company name':'اسم العميل','Network name':'اسم الشبكة','Owner name':'اسم المالك','WhatsApp':'واتساب','Country':'الدولة','City':'المدينة',
  'Address':'العنوان','Notes':'ملاحظات','Admin username':'اسم مستخدم المدير','Admin password':'كلمة مرور المدير','Registered':'تاريخ التسجيل',
  'Trial ends':'نهاية التجربة','Subscription ends':'نهاية الاشتراك','Reset password link':'رابط إعادة تعيين كلمة المرور','Export':'تصدير',
  'Full name':'الاسم الكامل','Username':'اسم المستخدم','Package':'الباقة','Payment status':'حالة الدفع','Paid':'مدفوع','Unpaid':'غير مدفوع','Partial':'مدفوع جزئياً',
  'Location':'الموقع','Account type':'نوع الحساب','Service type':'نوع الخدمة','Subscription start':'بداية الاشتراك','Customer ID':'رقم المشترك',
  'Role':'الدور','Permissions':'الصلاحيات','Current password':'كلمة المرور الحالية','New password':'كلمة مرور جديدة','Confirm new password':'تأكيد كلمة المرور',
  'Change password':'تغيير كلمة المرور','Active sessions':'الجلسات النشطة','Logout other sessions':'خروج من الأجهزة الأخرى','Login history':'سجل الدخول',
  'Invalid credentials':'بيانات الدخول غير صحيحة','Account locked, try later':'الحساب مقفل مؤقتاً، حاول لاحقاً','Company is suspended':'حساب العميل موقوف',
  'Too many attempts':'محاولات كثيرة، حاول لاحقاً','Saved':'تم الحفظ','Deleted':'تم الحذف','Forbidden':'غير مسموح','Not found':'غير موجود',
  'pw_short':'كلمة المرور أقل من 8 أحرف','pw_weak':'كلمة المرور لازم فيها حرف كبير وصغير ورقم','pw_mismatch':'تأكيد كلمة المرور غير مطابق',
  'Generate password':'توليد كلمة مرور','Copy':'نسخ','Copied':'تم النسخ','Copy it now: it is shown only once.':'انسخها الآن: بتظهر مرة واحدة بس.','pw_wrong':'كلمة المرور الحالية غير صحيحة','required':'حقل مطلوب','duplicate':'القيمة موجودة بالفعل','Previous':'السابق','Next':'التالي',
  'Language':'اللغة','All':'الكل','Welcome':'مرحباً','No results':'لا توجد نتائج','Company profile':'ملف العميل','Sessions':'الجلسات',
  'Super admin':'مدير المنصة','Company admin':'مدير العميل','Employee':'موظف','Created':'تم الإنشاء','Updated':'تم التحديث',
  'Link valid for 24 hours. Give it to the client admin. It can be used once.':'الرابط صالح 24 ساعة ويُستخدم مرة واحدة. أعطه لمدير العميل.',
  'Set new password':'تعيين كلمة مرور جديدة','Password updated, you can sign in':'تم تحديث كلمة المرور، سجل الدخول','Invalid or expired link':'رابط غير صالح أو منتهي',
  'Employees limit':'حد الموظفين','Company Manager':'مدير العميل','Network Administrator':'مسؤول الشبكة','Technical Support':'دعم فني','Sales Employee':'مبيعات','Cashier':'كاشير','Read-only Employee':'مشاهدة فقط',
  'customers.view':'عرض المشتركين','customers.add':'إضافة مشتركين','customers.edit':'تعديل مشتركين','customers.delete':'حذف مشتركين','audit.view':'عرض سجل النشاط','customers.export':'تصدير المشتركين'
};
Object.assign(ar, require('./i18n_plans'), require('./i18n_devices'), require('./i18n_pay'), require('./i18n_rep'), require('./i18n_sec'));
function make(lang) {
  const rtl = lang === 'ar';
  return { lang, rtl, t: (k) => (rtl && ar[k]) || (rtl ? k : String(k).replace(/Companies/g, 'Clients').replace(/Company/g, 'Client').replace(/companies/g, 'clients').replace(/company/g, 'client')) };
}
module.exports = { make };
