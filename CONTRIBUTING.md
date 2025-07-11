# دليل المساهمة في IP-Scan

شكرًا لاهتمامك بالمساهمة في تطوير IP-Scan! هذا الدليل يوضح كيفية المساهمة في المشروع وتحسينه.

## كيفية المساهمة

هناك العديد من الطرق للمساهمة في مشروع IP-Scan:

1. **تحسين الكود**: إصلاح الأخطاء، تحسين الأداء، إضافة ميزات جديدة
2. **تحسين الوثائق**: تحديث الوثائق، إضافة أمثلة، كتابة دروس تعليمية
3. **اختبار البرنامج**: اكتشاف الأخطاء، اقتراح تحسينات لواجهة المستخدم
4. **الترجمة**: ترجمة البرنامج والوثائق إلى لغات أخرى
5. **تقديم أفكار**: اقتراح ميزات جديدة أو تحسينات للميزات الحالية

## خطوات المساهمة

### 1. إعداد بيئة التطوير

1. قم بتثبيت Python 3.6 أو أحدث
2. قم بتثبيت Git
3. انسخ المستودع (Fork the repository)
4. قم بتنزيل النسخة المحلية (Clone your fork):
   ```
   git clone https://github.com/your-username/ip-scan.git
   cd ip-scan
   ```
5. قم بتثبيت المتطلبات:
   ```
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # متطلبات التطوير إذا كانت موجودة
   ```

### 2. العمل على التغييرات

1. قم بإنشاء فرع جديد (branch) للعمل عليه:
   ```
   git checkout -b feature/your-feature-name
   ```
   أو
   ```
   git checkout -b fix/issue-description
   ```

2. قم بإجراء التغييرات المطلوبة
3. تأكد من أن الكود يعمل بشكل صحيح
4. أضف اختبارات للميزات الجديدة إذا أمكن
5. قم بتحديث الوثائق حسب الحاجة

### 3. تقديم التغييرات

1. قم بإضافة التغييرات:
   ```
   git add .
   ```
2. قم بعمل commit:
   ```
   git commit -m "وصف مختصر للتغييرات"
   ```
3. قم برفع التغييرات إلى المستودع الخاص بك:
   ```
   git push origin feature/your-feature-name
   ```
4. قم بإنشاء طلب سحب (Pull Request) من خلال واجهة GitHub

## إرشادات الكود

### أسلوب الكود

- اتبع معيار PEP 8 لكتابة كود Python
- استخدم التعليقات بشكل مناسب لشرح الأجزاء المعقدة من الكود
- اكتب رسائل commit واضحة ومختصرة
- قم بتوثيق الدوال والفئات الجديدة

### الاختبارات

- حاول إضافة اختبارات للميزات الجديدة
- تأكد من أن جميع الاختبارات الحالية تنجح بعد التغييرات

### الوثائق

- قم بتحديث ملفات الوثائق (README.md، دليل_الاستخدام.md، إلخ) حسب الحاجة
- أضف تعليقات docstring للدوال والفئات الجديدة

## إرشادات الإبلاغ عن الأخطاء

إذا وجدت خطأً في البرنامج، يرجى الإبلاغ عنه مع توفير المعلومات التالية:

1. وصف مختصر وواضح للمشكلة
2. خطوات إعادة إنتاج المشكلة
3. السلوك المتوقع والسلوك الفعلي
4. معلومات النظام (نظام التشغيل، إصدار Python، إلخ)
5. لقطات شاشة إذا كان ذلك مناسبًا

## اقتراح ميزات جديدة

إذا كانت لديك فكرة لميزة جديدة، يرجى توفير المعلومات التالية:

1. وصف مفصل للميزة المقترحة
2. سبب أهمية هذه الميزة
3. أمثلة على كيفية استخدام الميزة
4. أي موارد أو مراجع ذات صلة

## عملية المراجعة

بعد تقديم طلب السحب (Pull Request)، سيتم مراجعته من قبل المشرفين على المشروع. قد يطلبون منك إجراء تغييرات قبل دمج التغييرات في الفرع الرئيسي.

## مدونة السلوك

nحن نتوقع من جميع المساهمين الالتزام بمدونة السلوك التالية:

- احترام جميع المساهمين الآخرين
- تقديم نقد بناء ومفيد
- التركيز على ما هو أفضل للمجتمع
- إظهار التعاطف تجاه أعضاء المجتمع الآخرين

## الترخيص

بالمساهمة في هذا المشروع، فإنك توافق على ترخيص مساهمتك بموجب ترخيص MIT.

---

شكرًا لمساهمتك في تطوير IP-Scan! إذا كانت لديك أي أسئلة، يرجى التواصل مع المطور:

**المبرمج**: Sayerlinux  
**البريد الإلكتروني**: SayersLinux@gmail.com