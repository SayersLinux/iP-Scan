@echo off
echo تشغيل IP-Scan (واجهة سطر الأوامر)...
echo المبرمج: Sayerlinux
echo البريد الإلكتروني: SayersLinux@gmail.com
echo.

REM يمكنك تعديل المعلمات أدناه حسب احتياجاتك
python cli.py -s 22.222.0.101 -e 22.222.0.200 -p 80,443,22,21,25,3306 -t 0.5 -th 200 -v

pause