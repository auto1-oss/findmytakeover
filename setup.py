#!/usr/bin/env python3
"""Setup configuration for findmytakeover package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="findmytakeover",
    version="2.0.0",
    author="Original Authors",
    description="A tool to find subdomain takeover vulnerabilities across AWS, Azure, and GCP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/auto1-oss/findmytakeover",
    license="GPL-3.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        # AWS Dependencies
        "boto3>=1.35.0",
        "botocore>=1.35.0",
        # Azure Dependencies
        "azure-identity>=1.15.0",
        "azure-mgmt-apimanagement>=4.0.0",
        "azure-mgmt-cdn>=12.0.0",
        "azure-mgmt-containerinstance>=10.1.0",
        "azure-mgmt-containerregistry>=10.3.0",
        "azure-mgmt-dns>=8.1.0",
        "azure-mgmt-network>=25.0.0",
        "azure-mgmt-redis>=14.0.0",
        "azure-mgmt-resource>=23.0.0",
        "azure-mgmt-search>=9.0.0",
        "azure-mgmt-sql>=3.0.0,<4.0.0",
        "azure-mgmt-storage>=21.0.0",
        "azure-mgmt-trafficmanager>=1.1.0",
        "azure-mgmt-web>=7.0.0",
        # GCP Dependencies
        "google-auth>=2.20.0",
        "google-cloud-compute>=1.14.0",
        "google-cloud-dns>=0.35.0",
        "google-cloud-functions>=1.13.0",
        "google-cloud-storage>=2.10.0",
        # Common Dependencies
        "dnspython>=2.4.0",
        "pandas>=2.0.0",
        "PyYAML>=6.0",
        "tqdm>=4.65.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "findmytakeover=findmytakeover.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords="security cloud aws azure gcp subdomain takeover dns dnssec",
    project_urls={
        "Bug Reports": "https://github.com/auto1-oss/findmytakeover/issues",
        "Source": "https://github.com/auto1-oss/findmytakeover",
    },
)
