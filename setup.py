from setuptools import setup, find_packages

setup(
    name="secure_messenger",
    version="0.1.0",
    description="Secure Messenger Backend API",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "fastapi==0.116.1",
        "uvicorn[standard]==0.35.0",
        "sqlalchemy==2.0.42",
        "aiosqlite==0.21.0",
        "environs==14.2.0",
        "python-jose[cryptography]==3.5.0",
        "pydantic==2.11.7"
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "messenger-api=main:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)