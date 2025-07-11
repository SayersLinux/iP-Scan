from setuptools import setup, find_packages
import os

# قراءة محتوى ملف README.md إذا كان موجودًا
long_description = ""
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()

# قراءة متطلبات التثبيت من ملف requirements.txt إذا كان موجودًا
requirements = [
    "PyQt5>=5.15.0",
    "ipaddress>=1.0.0",
    "requests>=2.25.0",
    "colorama>=0.4.4",
    "psutil>=5.8.0",
    "tqdm>=4.62.0",
]

setup(
    name="ip-scan",
    version="1.0.0",
    description="أداة قوية وسريعة لفحص عناوين IP والكشف عن المنافذ المفتوحة",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Sayerlinux",
    author_email="SayersLinux@gmail.com",
    url="https://github.com/Sayerlinux/ip-Scan",
    packages=find_packages(),
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'ip-scan=ip_scan:main',
            'ip-scan-cli=cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Natural Language :: Arabic",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires='>=3.6',
    include_package_data=True,
    package_data={
        "": ["icon.svg"],
    },
)