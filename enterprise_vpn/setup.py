"""Setup file for enterprise VPN package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README content
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="enterprise_vpn",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "wireguard",  # Using existing wireguard package
        "requests>=2.26.0",  # For Okta API calls
        "python-dotenv>=0.19.0",  # For configuration management
        "pyyaml>=6.0.1",  # For configuration files
        "psutil>=5.9.0",  # For system metrics collection
        "rich>=10.0.0",  # For beautiful terminal output
        "cryptography>=3.4.0",  # For secure key management
        "pynacl>=1.4.0",  # For cryptographic operations
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "mypy>=1.0.0",
            "pylint>=2.17.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "enterprise-vpn=enterprise_vpn.presentation.cli:cli",
            "enterprise-vpn-server=enterprise_vpn.presentation.server_cli:server",
        ],
    },
    author="Enterprise VPN Team",
    author_email="support@enterprise-vpn.com",
    description="Enterprise VPN solution using WireGuard",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="vpn, wireguard, enterprise, security",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
) 