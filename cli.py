#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP-Scan CLI: نسخة سطر الأوامر من أداة IP-Scan
المبرمج: Sayerlinux
البريد الإلكتروني: SayersLinux@gmail.com
"""

import sys
import socket
import ipaddress
import threading
import queue
import time
import argparse
import os
from datetime import datetime


class PortScanner:
    def __init__(self, ip_range, ports, timeout=1.0, max_threads=100, verbose=False):
        self.ip_range = ip_range
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.verbose = verbose
        self.results = {}
        self.stop_flag = False
        self.scanned_ips = 0
        self.total_ips = 0

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
            if self.verbose:
                ports_str = ", ".join(map(str, open_ports))
                print(f"[+] {ip}: المنافذ المفتوحة: {ports_str}")

    def scan(self):
        try:
            # تحويل نطاق IP إلى قائمة من عناوين IP
            start_ip = ipaddress.IPv4Address(self.ip_range[0])
            end_ip = ipaddress.IPv4Address(self.ip_range[1])
            
            self.total_ips = int(end_ip) - int(start_ip) + 1
            self.scanned_ips = 0
            
            print(f"[*] بدء المسح: من {start_ip} إلى {end_ip} ({self.total_ips} عنوان IP)")
            print(f"[*] المنافذ المستهدفة: {', '.join(map(str, self.ports))}")
            print(f"[*] عدد الخيوط: {self.max_threads}")
            print(f"[*] مهلة الاتصال: {self.timeout} ثانية")
            print("-" * 60)
            
            start_time = time.time()
            
            # إنشاء قائمة انتظار للعناوين
            ip_queue = queue.Queue()
            
            # إضافة جميع عناوين IP إلى قائمة الانتظار
            current_ip = start_ip
            while current_ip <= end_ip:
                if self.stop_flag:
                    break
                ip_queue.put(str(current_ip))
                current_ip += 1
            
            # إنشاء مجموعة من الخيوط للمسح
            def worker():
                while not self.stop_flag:
                    try:
                        ip = ip_queue.get(block=False)
                        self.scan_ip(ip)
                        ip_queue.task_done()
                        self.scanned_ips += 1
                        progress = int((self.scanned_ips / self.total_ips) * 100)
                        if self.verbose and self.scanned_ips % 10 == 0:
                            print(f"[*] تقدم المسح: {progress}% ({self.scanned_ips}/{self.total_ips})")
                    except queue.Empty:
                        break
                    except Exception as e:
                        if self.verbose:
                            print(f"[!] خطأ في العامل: {e}")
            
            # بدء الخيوط
            threads = []
            thread_count = min(self.max_threads, self.total_ips)
            for _ in range(thread_count):
                t = threading.Thread(target=worker)
                t.daemon = True
                threads.append(t)
                t.start()
            
            # انتظار انتهاء جميع الخيوط
            for t in threads:
                t.join()
                
            end_time = time.time()
            duration = end_time - start_time
            
            print("-" * 60)
            print(f"[*] اكتمل المسح في {duration:.2f} ثانية")
            print(f"[*] تم العثور على {len(self.results)} عنوان IP بمنافذ مفتوحة")
            
            return self.results
            
        except KeyboardInterrupt:
            print("\n[!] تم إيقاف المسح بواسطة المستخدم")
            self.stop_flag = True
            return self.results
        except Exception as e:
            print(f"[!] خطأ في المسح: {e}")
            return self.results

    def export_results(self, file_path):
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("IP-Scan: نتائج فحص المنافذ المفتوحة\n")
                f.write("المبرمج: Sayerlinux | البريد الإلكتروني: SayersLinux@gmail.com\n")
                f.write(f"تاريخ المسح: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                
                for ip, ports in self.results.items():
                    f.write(f"عنوان IP: {ip}\n")
                    f.write(f"المنافذ المفتوحة: {', '.join(map(str, ports))}\n\n")
                    
            print(f"[+] تم تصدير النتائج بنجاح إلى: {file_path}")
            return True
        except Exception as e:
            print(f"[!] خطأ أثناء تصدير النتائج: {e}")
            return False


def parse_ports(ports_str):
    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


def validate_ip_range(start_ip, end_ip):
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        
        if start > end:
            print("[!] خطأ: عنوان IP البداية يجب أن يكون أقل من أو يساوي عنوان IP النهاية")
            return None
            
        # التحقق من أن نطاق IP ضمن النطاق المطلوب
        min_ip = ipaddress.IPv4Address("22.222.0.101")
        max_ip = ipaddress.IPv4Address("212.255.255.255")
        
        if start < min_ip:
            print(f"[!] خطأ: عنوان IP البداية يجب أن يكون أكبر من أو يساوي {min_ip}")
            return None
            
        if end > max_ip:
            print(f"[!] خطأ: عنوان IP النهاية يجب أن يكون أقل من أو يساوي {max_ip}")
            return None
            
        return (str(start), str(end))
    except Exception as e:
        print(f"[!] خطأ في عنوان IP: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="IP-Scan: أداة لفحص عناوين IP والمنافذ المفتوحة")
    parser.add_argument("-s", "--start", required=True, help="عنوان IP البداية")
    parser.add_argument("-e", "--end", required=True, help="عنوان IP النهاية")
    parser.add_argument("-p", "--ports", default="21,22,23,25,80,443,3306,8080", 
                        help="المنافذ المراد فحصها (مفصولة بفواصل، يمكن استخدام النطاقات مثل 80-100)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, 
                        help="مهلة الاتصال بالثواني (الافتراضي: 1.0)")
    parser.add_argument("-th", "--threads", type=int, default=100, 
                        help="عدد الخيوط المتزامنة (الافتراضي: 100)")
    parser.add_argument("-o", "--output", help="ملف لتصدير النتائج")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="عرض معلومات مفصلة أثناء المسح")
    
    args = parser.parse_args()
    
    # التحقق من صحة نطاق IP
    ip_range = validate_ip_range(args.start, args.end)
    if not ip_range:
        return 1
    
    # تحليل المنافذ
    try:
        ports = parse_ports(args.ports)
        if not ports:
            print("[!] خطأ: يرجى تحديد منفذ واحد على الأقل")
            return 1
            
        # التحقق من صحة المنافذ
        for port in ports:
            if port < 1 or port > 65535:
                print(f"[!] خطأ: المنفذ {port} خارج النطاق المسموح (1-65535)")
                return 1
    except Exception as e:
        print(f"[!] خطأ في تحليل المنافذ: {e}")
        return 1
    
    # بدء المسح
    scanner = PortScanner(ip_range, ports, args.timeout, args.threads, args.verbose)
    results = scanner.scan()
    
    # تصدير النتائج إذا تم تحديد ملف الإخراج
    if args.output and results:
        scanner.export_results(args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())