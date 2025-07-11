#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP-Scan: أداة قوية لفحص عناوين IP والمنافذ المفتوحة
المبرمج: Sayerlinux
البريد الإلكتروني: SayersLinux@gmail.com
"""

import sys
import socket
import ipaddress
import threading
import queue
import time
import os
import json
import csv
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QSpinBox, QCheckBox, QMessageBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QTabWidget, QFileDialog, QGroupBox, QGridLayout,
                             QFormLayout, QComboBox, QDoubleSpinBox, QSplitter, QMenu, QAction,
                             QInputDialog, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSettings, QSize
from PyQt5.QtGui import QIcon, QFont, QColor, QPixmap, QTextCursor, QPalette


# قاموس للخدمات الشائعة
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy"
}


class PortScannerThread(QThread):
    update_signal = pyqtSignal(str, list)
    progress_signal = pyqtSignal(int)
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, ip_range, ports, timeout=1.0, max_threads=100):
        super().__init__()
        self.ip_range = ip_range
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.stop_flag = False
        self.results = {}

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
            return None
        except:
            return None

    def scan_ip(self, ip):
        open_ports = []
        for port in self.ports:
            if self.stop_flag:
                return
            result = self.scan_port(ip, port)
            if result:
                open_ports.append(result)
        
        if open_ports:
            self.results[ip] = open_ports
            self.update_signal.emit(ip, open_ports)

    def run(self):
        try:
            # تحويل نطاق IP إلى قائمة من عناوين IP
            start_ip = ipaddress.IPv4Address(self.ip_range[0])
            end_ip = ipaddress.IPv4Address(self.ip_range[1])
            
            total_ips = int(end_ip) - int(start_ip) + 1
            scanned_ips = 0
            
            self.status_signal.emit(f"بدء المسح: من {self.ip_range[0]} إلى {self.ip_range[1]} ({total_ips} عنوان IP)")
            
            # إنشاء قائمة انتظار للعناوين
            ip_queue = queue.Queue()
            
            # إضافة جميع عناوين IP إلى قائمة الانتظار
            current_ip = start_ip
            while current_ip <= end_ip:
                if self.stop_flag:
                    break
                ip_queue.put(str(current_ip))
                current_ip += 1
            
            # إنشاء قفل للتزامن
            lock = threading.Lock()
            
            # إنشاء مجموعة من الخيوط للمسح
            def worker():
                while not self.stop_flag:
                    try:
                        ip = ip_queue.get(block=False)
                        self.scan_ip(ip)
                        ip_queue.task_done()
                        nonlocal scanned_ips
                        with lock:
                            scanned_ips += 1
                            progress = int((scanned_ips / total_ips) * 100)
                            self.progress_signal.emit(progress)
                    except queue.Empty:
                        break
                    except Exception as e:
                        self.status_signal.emit(f"خطأ في العامل: {str(e)}")
            
            # بدء الخيوط
            threads = []
            thread_count = min(self.max_threads, total_ips)
            for _ in range(thread_count):
                if self.stop_flag:
                    break
                t = threading.Thread(target=worker)
                t.daemon = True
                threads.append(t)
                t.start()
            
            # انتظار انتهاء جميع الخيوط
            for t in threads:
                t.join()
            
            if not self.stop_flag:
                self.status_signal.emit(f"اكتمل المسح. تم العثور على {len(self.results)} عنوان IP بمنافذ مفتوحة")
                self.finished_signal.emit()
            else:
                self.status_signal.emit("تم إيقاف المسح بواسطة المستخدم")
                self.finished_signal.emit()
                
        except Exception as e:
            self.status_signal.emit(f"خطأ في المسح: {str(e)}")
            self.finished_signal.emit()

    def stop(self):
        self.stop_flag = True


class IPScanApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP-Scan - أداة فحص عناوين IP والمنافذ المفتوحة")
        self.setMinimumSize(800, 600)
        
        # تعيين أيقونة التطبيق
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.svg")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        
        # إنشاء الإعدادات
        self.settings = QSettings("Sayerlinux", "IP-Scan")
        
        # إنشاء الواجهة الرئيسية
        self.init_ui()
        
        # متغيرات للتحكم في المسح
        self.scanner_thread = None
        self.scan_results = {}
        
        # تحميل الإعدادات
        self.load_settings()
        
    def init_ui(self):
        # إنشاء الويدجت الرئيسي
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # إنشاء شريط التبويب
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # إنشاء تبويبات
        self.setup_scan_tab()
        self.setup_results_tab()
        self.setup_settings_tab()
        self.setup_about_tab()
        
        # إنشاء شريط الحالة
        self.statusBar().showMessage("جاهز")
        
    def setup_scan_tab(self):
        # إنشاء تبويب المسح
        scan_tab = QWidget()
        self.tab_widget.addTab(scan_tab, "المسح")
        scan_layout = QVBoxLayout(scan_tab)
        
        # إنشاء مجموعة إعدادات المسح
        scan_group = QGroupBox("إعدادات المسح")
        scan_form = QFormLayout(scan_group)
        
        # إضافة حقول الإدخال
        ip_range_layout = QHBoxLayout()
        self.start_ip_input = QLineEdit()
        self.start_ip_input.setPlaceholderText("22.222.0.101")
        ip_range_layout.addWidget(self.start_ip_input)
        
        ip_range_layout.addWidget(QLabel("إلى"))
        
        self.end_ip_input = QLineEdit()
        self.end_ip_input.setPlaceholderText("22.222.0.200")
        ip_range_layout.addWidget(self.end_ip_input)
        
        scan_form.addRow("نطاق عناوين IP:", ip_range_layout)
        
        # إضافة حقل المنافذ
        ports_layout = QVBoxLayout()
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("21,22,23,25,53,80,443,3306,8080 أو 1-1024")
        ports_layout.addWidget(self.ports_input)
        
        # خيار المنافذ الشائعة
        self.common_ports_check = QCheckBox("استخدام المنافذ الشائعة")
        self.common_ports_check.stateChanged.connect(self.toggle_common_ports)
        ports_layout.addWidget(self.common_ports_check)
        
        scan_form.addRow("المنافذ:", ports_layout)
        
        # إضافة إعدادات المسح
        scan_settings_layout = QHBoxLayout()
        
        timeout_layout = QHBoxLayout()
        timeout_layout.addWidget(QLabel("مهلة الاتصال:"))
        self.timeout_input = QDoubleSpinBox()
        self.timeout_input.setRange(0.1, 10.0)
        self.timeout_input.setSingleStep(0.1)
        self.timeout_input.setValue(1.0)
        self.timeout_input.setSuffix(" ثانية")
        timeout_layout.addWidget(self.timeout_input)
        
        scan_settings_layout.addLayout(timeout_layout)
        
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("عدد الخيوط:"))
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 500)
        self.threads_input.setValue(100)
        threads_layout.addWidget(self.threads_input)
        
        scan_settings_layout.addLayout(threads_layout)
        
        scan_form.addRow("", scan_settings_layout)
        
        scan_layout.addWidget(scan_group)
        
        # أزرار التحكم
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("بدء المسح")
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("إيقاف المسح")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        self.clear_button = QPushButton("مسح النتائج")
        self.clear_button.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_button)
        
        scan_layout.addLayout(button_layout)
        
        # شريط التقدم
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        scan_layout.addLayout(progress_layout)
        
        # سجل المسح
        scan_layout.addWidget(QLabel("سجل المسح:"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        scan_layout.addWidget(self.log_text)
    
    def setup_results_tab(self):
        # إنشاء تبويب النتائج
        results_tab = QWidget()
        self.tab_widget.addTab(results_tab, "النتائج")
        results_layout = QVBoxLayout(results_tab)
        
        # جدول النتائج
        self.results_table = QTableWidget(0, 3)
        self.results_table.setHorizontalHeaderLabels(["عنوان IP", "المنافذ المفتوحة", "الخدمات"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_results_context_menu)
        results_layout.addWidget(self.results_table)
        
        # أزرار التصدير
        export_layout = QHBoxLayout()
        
        self.export_txt_button = QPushButton("تصدير كنص (.txt)")
        self.export_txt_button.clicked.connect(lambda: self.export_results("txt"))
        export_layout.addWidget(self.export_txt_button)
        
        self.export_csv_button = QPushButton("تصدير كـ CSV (.csv)")
        self.export_csv_button.clicked.connect(lambda: self.export_results("csv"))
        export_layout.addWidget(self.export_csv_button)
        
        self.export_json_button = QPushButton("تصدير كـ JSON (.json)")
        self.export_json_button.clicked.connect(lambda: self.export_results("json"))
        export_layout.addWidget(self.export_json_button)
        
        results_layout.addLayout(export_layout)
    
    def setup_settings_tab(self):
        # إنشاء تبويب الإعدادات
        settings_tab = QWidget()
        self.tab_widget.addTab(settings_tab, "الإعدادات")
        settings_layout = QVBoxLayout(settings_tab)
        
        # مجموعة الإعدادات العامة
        general_group = QGroupBox("الإعدادات العامة")
        general_form = QFormLayout(general_group)
        
        # حفظ الإعدادات تلقائيًا
        self.save_settings_check = QCheckBox("حفظ الإعدادات تلقائيًا")
        general_form.addRow("", self.save_settings_check)
        
        # مجلد الحفظ الافتراضي
        save_dir_layout = QHBoxLayout()
        self.default_save_dir_input = QLineEdit()
        self.default_save_dir_input.setReadOnly(True)
        save_dir_layout.addWidget(self.default_save_dir_input)
        
        self.browse_save_dir_button = QPushButton("تصفح...")
        self.browse_save_dir_button.clicked.connect(self.browse_save_directory)
        save_dir_layout.addWidget(self.browse_save_dir_button)
        
        general_form.addRow("مجلد الحفظ الافتراضي:", save_dir_layout)
        
        settings_layout.addWidget(general_group)
        
        # مجموعة إعدادات المسح الافتراضية
        default_scan_group = QGroupBox("إعدادات المسح الافتراضية")
        default_scan_form = QFormLayout(default_scan_group)
        
        # المنافذ الافتراضية
        self.default_ports_input = QLineEdit()
        default_scan_form.addRow("المنافذ الافتراضية:", self.default_ports_input)
        
        # مهلة الاتصال الافتراضية
        self.default_timeout_spin = QDoubleSpinBox()
        self.default_timeout_spin.setRange(0.1, 10.0)
        self.default_timeout_spin.setSingleStep(0.1)
        self.default_timeout_spin.setSuffix(" ثانية")
        default_scan_form.addRow("مهلة الاتصال الافتراضية:", self.default_timeout_spin)
        
        # عدد الخيوط الافتراضي
        self.default_threads_spin = QSpinBox()
        self.default_threads_spin.setRange(1, 500)
        default_scan_form.addRow("عدد الخيوط الافتراضي:", self.default_threads_spin)
        
        settings_layout.addWidget(default_scan_group)
        
        # أزرار الإعدادات
        settings_buttons_layout = QHBoxLayout()
        
        self.save_settings_button = QPushButton("حفظ الإعدادات")
        self.save_settings_button.clicked.connect(self.save_settings)
        settings_buttons_layout.addWidget(self.save_settings_button)
        
        self.reset_settings_button = QPushButton("إعادة تعيين الإعدادات")
        self.reset_settings_button.clicked.connect(self.reset_settings)
        settings_buttons_layout.addWidget(self.reset_settings_button)
        
        settings_layout.addLayout(settings_buttons_layout)
        settings_layout.addStretch()
    
    def setup_about_tab(self):
        # إنشاء تبويب حول البرنامج
        about_tab = QWidget()
        self.tab_widget.addTab(about_tab, "حول البرنامج")
        about_layout = QVBoxLayout(about_tab)
        
        # عنوان البرنامج
        title_label = QLabel("IP-Scan")
        title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        about_layout.addWidget(title_label)
        
        # وصف البرنامج
        desc_label = QLabel("أداة قوية لفحص عناوين IP والمنافذ المفتوحة")
        desc_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(desc_label)
        
        # معلومات المطور
        dev_info = QLabel("المطور: Sayerlinux\nالبريد الإلكتروني: SayersLinux@gmail.com")
        dev_info.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(dev_info)
        
        # إصدار البرنامج
        version_label = QLabel("الإصدار: 1.0.0")
        version_label.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(version_label)
        
        about_layout.addStretch()
        
        # معلومات إضافية
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setHtml("""
        <div dir="rtl" style="text-align: center;">
            <h3>ميزات البرنامج</h3>
            <ul style="text-align: right;">
                <li>فحص نطاق واسع من عناوين IP</li>
                <li>اكتشاف المنافذ المفتوحة</li>
                <li>واجهة مستخدم رسومية سهلة الاستخدام</li>
                <li>إمكانية تصدير النتائج بتنسيقات متعددة</li>
                <li>خيارات تخصيص متقدمة</li>
                <li>أداء عالي مع دعم المسح المتوازي</li>
            </ul>
            
            <h3>تنبيه هام</h3>
            <p>يرجى استخدام هذه الأداة بمسؤولية وفقط على الشبكات المصرح لك بفحصها.</p>
            <p>قد يكون فحص الشبكات دون إذن مخالفًا للقانون في بعض البلدان.</p>
        </div>
        """)
        about_layout.addWidget(info_text)
        
        # إضافة العناصر إلى التخطيط الرئيسي
        main_layout.addWidget(scan_group)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(QLabel("النتائج:"))
        main_layout.addWidget(self.results_table)
        
        # إضافة معلومات المبرمج
        info_label = QLabel("المبرمج: Sayerlinux | البريد الإلكتروني: SayersLinux@gmail.com")
        info_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(info_label)
    
    def validate_ip_range(self):
        try:
            start_ip = ipaddress.IPv4Address(self.start_ip_input.text())
            end_ip = ipaddress.IPv4Address(self.end_ip_input.text())
            
            if start_ip > end_ip:
                QMessageBox.warning(self, "خطأ", "عنوان IP البداية يجب أن يكون أقل من أو يساوي عنوان IP النهاية")
                return None
                
            # التحقق من أن نطاق IP ضمن النطاق المطلوب
            min_ip = ipaddress.IPv4Address("22.222.0.101")
            max_ip = ipaddress.IPv4Address("212.255.255.255")
            
            if start_ip < min_ip:
                QMessageBox.warning(self, "خطأ", f"عنوان IP البداية يجب أن يكون أكبر من أو يساوي {min_ip}")
                return None
                
            if end_ip > max_ip:
                QMessageBox.warning(self, "خطأ", f"عنوان IP النهاية يجب أن يكون أقل من أو يساوي {max_ip}")
                return None
                
            return (str(start_ip), str(end_ip))
        except Exception as e:
            QMessageBox.warning(self, "خطأ", f"عنوان IP غير صالح: {e}")
            return None
    
    def parse_ports(self):
        try:
            ports_text = self.ports_input.text().strip()
            if not ports_text:
                QMessageBox.warning(self, "خطأ", "يرجى تحديد منفذ واحد على الأقل")
                return None
                
            ports = []
            for part in ports_text.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
                    
            # التحقق من صحة المنافذ
            for port in ports:
                if port < 1 or port > 65535:
                    QMessageBox.warning(self, "خطأ", f"المنفذ {port} خارج النطاق المسموح (1-65535)")
                    return None
                    
            return ports
        except Exception as e:
            QMessageBox.warning(self, "خطأ", f"خطأ في تحليل المنافذ: {e}")
            return None
    
    def start_scan(self):
        # التحقق من صحة المدخلات
        ip_range = self.validate_ip_range()
        if not ip_range:
            return
            
        ports = self.parse_ports()
        if not ports:
            return
            
        # تحديث واجهة المستخدم
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        self.scan_results = {}
        self.log_text.clear()
        
        # بدء المسح
        timeout = self.timeout_input.value()
        max_threads = self.threads_input.value()
        
        # إضافة معلومات المسح إلى السجل
        self.log_message(f"بدء المسح من {ip_range[0]} إلى {ip_range[1]}")
        self.log_message(f"المنافذ: {len(ports)} منفذ")
        self.log_message(f"مهلة الاتصال: {timeout} ثانية")
        self.log_message(f"عدد الخيوط: {max_threads}")
        
        self.scanner_thread = PortScannerThread(ip_range, ports, timeout, max_threads)
        self.scanner_thread.update_signal.connect(self.update_results)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.status_signal.connect(self.log_message)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()
        
        # حفظ الإعدادات تلقائيًا إذا كان مفعلاً
        if self.save_settings_check.isChecked():
            self.save_settings()
    
    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.scanner_thread.wait()
            self.scan_finished()
    
    def load_settings(self):
        """
        تحميل الإعدادات المحفوظة
        """
        # تحميل إعدادات نطاق IP
        self.start_ip_input.setText(self.settings.value("start_ip", "22.222.0.101"))
        self.end_ip_input.setText(self.settings.value("end_ip", "22.222.0.200"))
        
        # تحميل إعدادات المنافذ
        self.ports_input.setText(self.settings.value("ports", "21,22,23,25,53,80,443,3306,8080"))
        self.common_ports_check.setChecked(self.settings.value("use_common_ports", False, type=bool))
        
        # تحميل إعدادات المسح
        self.timeout_input.setValue(self.settings.value("timeout", 1.0, type=float))
        self.threads_input.setValue(self.settings.value("threads", 100, type=int))
        
        # تحميل الإعدادات العامة
        self.save_settings_check.setChecked(self.settings.value("auto_save_settings", True, type=bool))
        self.default_save_dir_input.setText(self.settings.value("default_save_dir", os.path.dirname(os.path.abspath(__file__))))
        
        # تحميل إعدادات المسح الافتراضية
        self.default_ports_input.setText(self.settings.value("default_ports", "21,22,23,25,53,80,443,3306,8080"))
        self.default_timeout_spin.setValue(self.settings.value("default_timeout", 1.0, type=float))
        self.default_threads_spin.setValue(self.settings.value("default_threads", 100, type=int))
        
        # تطبيق إعدادات المنافذ الشائعة
        self.toggle_common_ports()
    
    def save_settings(self):
        """
        حفظ الإعدادات
        """
        # حفظ إعدادات نطاق IP
        self.settings.setValue("start_ip", self.start_ip_input.text())
        self.settings.setValue("end_ip", self.end_ip_input.text())
        
        # حفظ إعدادات المنافذ
        self.settings.setValue("ports", self.ports_input.text())
        self.settings.setValue("use_common_ports", self.common_ports_check.isChecked())
        
        # حفظ إعدادات المسح
        self.settings.setValue("timeout", self.timeout_input.value())
        self.settings.setValue("threads", self.threads_input.value())
        
        # حفظ الإعدادات العامة
        self.settings.setValue("auto_save_settings", self.save_settings_check.isChecked())
        self.settings.setValue("default_save_dir", self.default_save_dir_input.text())
        
        # حفظ إعدادات المسح الافتراضية
        self.settings.setValue("default_ports", self.default_ports_input.text())
        self.settings.setValue("default_timeout", self.default_timeout_spin.value())
        self.settings.setValue("default_threads", self.default_threads_spin.value())
        
        self.log_message("تم حفظ الإعدادات بنجاح")
    
    def reset_settings(self):
        """
        إعادة تعيين الإعدادات إلى القيم الافتراضية
        """
        # إعادة تعيين إعدادات نطاق IP
        self.start_ip_input.setText("22.222.0.101")
        self.end_ip_input.setText("22.222.0.200")
        
        # إعادة تعيين إعدادات المنافذ
        self.ports_input.setText("21,22,23,25,53,80,443,3306,8080")
        self.common_ports_check.setChecked(False)
        
        # إعادة تعيين إعدادات المسح
        self.timeout_input.setValue(1.0)
        self.threads_input.setValue(100)
        
        # إعادة تعيين الإعدادات العامة
        self.save_settings_check.setChecked(True)
        self.default_save_dir_input.setText(os.path.dirname(os.path.abspath(__file__)))
        
        # إعادة تعيين إعدادات المسح الافتراضية
        self.default_ports_input.setText("21,22,23,25,53,80,443,3306,8080")
        self.default_timeout_spin.setValue(1.0)
        self.default_threads_spin.setValue(100)
        
        # حفظ الإعدادات المعاد تعيينها
        self.save_settings()
        
        self.log_message("تم إعادة تعيين الإعدادات إلى القيم الافتراضية")
    
    def toggle_common_ports(self):
        """
        تبديل استخدام المنافذ الشائعة
        """
        if self.common_ports_check.isChecked():
            self.ports_input.setText("21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080")
            self.ports_input.setEnabled(False)
        else:
            self.ports_input.setEnabled(True)
    
    def browse_save_directory(self):
        """
        اختيار مجلد الحفظ الافتراضي
        """
        directory = QFileDialog.getExistingDirectory(self, "اختر مجلد الحفظ الافتراضي",
                                                  self.default_save_dir_input.text())
        if directory:
            self.default_save_dir_input.setText(directory)
    
    def log_message(self, message):
        """
        إضافة رسالة إلى السجل
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        # تمرير إلى نهاية النص
        self.log_text.moveCursor(QTextCursor.End)
        
    def update_results(self, ip, open_ports):
        # تحديث النتائج في الجدول
        self.scan_results[ip] = open_ports
        
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # إضافة عنوان IP
        ip_item = QTableWidgetItem(ip)
        self.results_table.setItem(row, 0, ip_item)
        
        # إضافة المنافذ المفتوحة
        ports_item = QTableWidgetItem(", ".join(map(str, open_ports)))
        self.results_table.setItem(row, 1, ports_item)
        
        # إضافة الخدمات
        services = [f"{port} ({COMMON_SERVICES.get(port, 'unknown')})" for port in open_ports]
        services_item = QTableWidgetItem(", ".join(services))
        self.results_table.setItem(row, 2, services_item)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def scan_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        
        self.log_message(f"اكتمل المسح. تم العثور على {len(self.scan_results)} عنوان IP بمنافذ مفتوحة")
        self.statusBar().showMessage(f"اكتمل المسح. تم العثور على {len(self.scan_results)} عنوان IP بمنافذ مفتوحة")
        
        # التبديل إلى تبويب النتائج إذا كانت هناك نتائج
        if len(self.scan_results) > 0:
            self.tab_widget.setCurrentIndex(1)  # تبويب النتائج
            QMessageBox.information(self, "اكتمل المسح", f"تم العثور على {len(self.scan_results)} عنوان IP بمنافذ مفتوحة")
    
    def clear_results(self):
        """
        مسح النتائج
        """
        self.results_table.setRowCount(0)
        self.scan_results = {}
        self.log_text.clear()
        self.progress_bar.setValue(0)
        self.statusBar().showMessage("جاهز")
    
    def show_results_context_menu(self, position):
        """
        عرض قائمة السياق لجدول النتائج
        """
        menu = QMenu()
        copy_action = menu.addAction("نسخ")
        export_selected_action = menu.addAction("تصدير المحدد")
        menu.addSeparator()
        clear_action = menu.addAction("مسح النتائج")
        
        action = menu.exec_(self.results_table.mapToGlobal(position))
        
        if action == copy_action:
            self.copy_selected_results()
        elif action == export_selected_action:
            self.export_selected_results()
        elif action == clear_action:
            self.clear_results()
    
    def copy_selected_results(self):
        """
        نسخ النتائج المحددة إلى الحافظة
        """
        selected_rows = set(index.row() for index in self.results_table.selectedIndexes())
        if not selected_rows:
            return
        
        text = ""
        for row in sorted(selected_rows):
            ip = self.results_table.item(row, 0).text()
            ports = self.results_table.item(row, 1).text()
            services = self.results_table.item(row, 2).text()
            text += f"IP: {ip}\nالمنافذ المفتوحة: {ports}\nالخدمات: {services}\n\n"
        
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("تم نسخ النتائج المحددة إلى الحافظة")
    
    def export_selected_results(self):
        """
        تصدير النتائج المحددة
        """
        selected_rows = set(index.row() for index in self.results_table.selectedIndexes())
        if not selected_rows:
            QMessageBox.warning(self, "تحذير", "لم يتم تحديد أي نتائج للتصدير")
            return
        
        # إنشاء قاموس للنتائج المحددة
        selected_results = {}
        for row in selected_rows:
            ip = self.results_table.item(row, 0).text()
            ports_str = self.results_table.item(row, 1).text()
            ports = [int(p.strip()) for p in ports_str.split(',')]
            selected_results[ip] = ports
        
        # فتح مربع حوار لاختيار تنسيق التصدير
        formats = ["نص (.txt)", "CSV (.csv)", "JSON (.json)"]
        format_choice, ok = QInputDialog.getItem(self, "اختر تنسيق التصدير", "التنسيق:", formats, 0, False)
        
        if ok and format_choice:
            if "txt" in format_choice:
                self.export_results("txt", selected_results)
            elif "csv" in format_choice:
                self.export_results("csv", selected_results)
            elif "json" in format_choice:
                self.export_results("json", selected_results)
    
    def export_results(self, format_type="txt", results_to_export=None):
        """
        تصدير النتائج إلى ملف
        """
        if not results_to_export:
            results_to_export = self.scan_results
        
        if not results_to_export:
            QMessageBox.warning(self, "تحذير", "لا توجد نتائج للتصدير")
            return
        
        # تحديد اسم الملف الافتراضي
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"ip_scan_results_{timestamp}"
        
        # تحديد مرشح الملف بناءً على التنسيق
        if format_type == "txt":
            file_filter = "ملفات نصية (*.txt)"
            default_filename += ".txt"
        elif format_type == "csv":
            file_filter = "ملفات CSV (*.csv)"
            default_filename += ".csv"
        elif format_type == "json":
            file_filter = "ملفات JSON (*.json)"
            default_filename += ".json"
        else:
            QMessageBox.warning(self, "خطأ", "تنسيق غير مدعوم")
            return
        
        # فتح مربع حوار حفظ الملف
        file_path, _ = QFileDialog.getSaveFileName(
            self, "حفظ النتائج", os.path.join(self.default_save_dir_input.text(), default_filename),
            file_filter
        )
        
        if not file_path:
            return
        
        try:
            if format_type == "txt":
                self.export_as_text(file_path, results_to_export)
            elif format_type == "csv":
                self.export_as_csv(file_path, results_to_export)
            elif format_type == "json":
                self.export_as_json(file_path, results_to_export)
            
            self.log_message(f"تم تصدير النتائج بنجاح إلى: {file_path}")
            self.statusBar().showMessage(f"تم تصدير النتائج بنجاح إلى: {file_path}")
            QMessageBox.information(self, "تم التصدير", f"تم تصدير النتائج بنجاح إلى:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "خطأ في التصدير", f"حدث خطأ أثناء تصدير النتائج: {str(e)}")
    
    def export_as_text(self, file_path, results):
        """
        تصدير النتائج كملف نصي
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("IP-Scan: نتائج فحص المنافذ المفتوحة\n")
            f.write("المبرمج: Sayerlinux | البريد الإلكتروني: SayersLinux@gmail.com\n")
            f.write(f"تاريخ المسح: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 50 + "\n\n")
            
            for ip, ports in results.items():
                f.write(f"عنوان IP: {ip}\n")
                f.write(f"المنافذ المفتوحة: {', '.join(map(str, ports))}\n")
                
                # إضافة معلومات الخدمات
                services = [f"{port} ({COMMON_SERVICES.get(port, 'unknown')})" for port in ports]
                f.write(f"الخدمات: {', '.join(services)}\n\n")
    
    def export_as_csv(self, file_path, results):
        """
        تصدير النتائج كملف CSV
        """
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Port", "Service"])
            
            for ip, ports in results.items():
                for port in ports:
                    service = COMMON_SERVICES.get(port, "unknown")
                    writer.writerow([ip, port, service])
    
    def export_as_json(self, file_path, results):
        """
        تصدير النتائج كملف JSON
        """
        json_results = {
            "scan_info": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "developer": "Sayerlinux",
                "email": "SayersLinux@gmail.com"
            },
            "results": {}
        }
        
        for ip, ports in results.items():
            json_results["results"][ip] = {
                "open_ports": ports,
                "services": {port: COMMON_SERVICES.get(port, "unknown") for port in ports}
            }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(json_results, f, ensure_ascii=False, indent=4)


    def closeEvent(self, event):
        """
        معالجة حدث إغلاق النافذة
        """
        # إيقاف المسح إذا كان قيد التشغيل
        if self.scanner_thread and self.scanner_thread.isRunning():
            reply = QMessageBox.question(self, "تأكيد الإغلاق",
                                       "المسح قيد التشغيل. هل تريد إيقافه وإغلاق البرنامج؟",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.scanner_thread.stop()
                self.scanner_thread.wait()
            else:
                event.ignore()
                return
        
        # حفظ الإعدادات تلقائيًا إذا كان مفعلاً
        if self.save_settings_check.isChecked():
            self.save_settings()
        
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # استخدام نمط Fusion للحصول على مظهر حديث
    
    # تعيين الخط للتطبيق
    font = QFont("Arial", 10)
    app.setFont(font)
    
    # تعيين أيقونة التطبيق
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.svg")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    window = IPScanApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()