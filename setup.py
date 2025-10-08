#!/usr/bin/env python3
"""
Forensic-Playbook Setup Script
"""

from pathlib import Path
from setuptools import find_packages, setup

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="forensic-playbook",
    version="2.0.0",
    description="Professional Digital Forensics Investigation Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Forensic-Playbook Contributors",
    author_email="forensic-playbook@example.com",
    url="https://github.com/your-org/Forensic-Playbook",
    license="MIT",
    
    # Packages
    packages=find_packages(exclude=["tests", "tests.*", "docs"]),
    include_package_data=True,
    
    # Requirements
    python_requires=">=3.10",
    install_requires=requirements,
    
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
            "sphinx>=5.0",
        ],
        "reporting": [
            "jinja2>=3.1",
            "matplotlib>=3.5",
            "plotly>=5.0",
            "weasyprint>=57.0",  # For PDF generation
        ],
        "cloud": [
            "boto3>=1.26",  # AWS
            "azure-storage-blob>=12.0",  # Azure
            "google-cloud-storage>=2.0",  # GCP
        ],
    },
    
    # Entry points
    entry_points={
        "console_scripts": [
            "forensic=scripts.forensic-cli:cli",
            "forensic-cli=scripts.forensic-cli:cli",
        ],
    },
    
    # Package data
    package_data={
        "forensic": [
            "config/*.yaml",
            "config/templates/*.j2",
            "config/iocs/*.json",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    
    # Keywords
    keywords="forensics security incident-response digital-forensics dfir",
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/your-org/Forensic-Playbook/issues",
        "Source": "https://github.com/your-org/Forensic-Playbook",
        "Documentation": "https://github.com/your-org/Forensic-Playbook/docs",
    },
)
