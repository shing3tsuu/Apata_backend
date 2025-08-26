Backend Service - Secure Messenger API
Overview

A secure, lightweight backend API for an end-to-end encrypted messaging platform built with FastAPI and PostgreSQL. This service acts as a temporary message relay and authentication provider while maintaining zero knowledge of message contents.
Architecture Overview
text

┌─────────────────┐    HTTPS/TLS     ┌────────────────────┐
│   Mobile/Desktop│ ◄──────────────► │   Backend API      │
│   Client        │                  │  (FastAPI + PostgreSQL)
│   (Flet + SQLite)│                  │                    │
└─────────────────┘                  └────────────────────┘
      │ 1. Encrypt & Send                   │ 2. Store Temp
      │ 3. Retrieve & Decrypt               │ 4. Auth & Manage
      │                                     │
┌─────────────────┐                  ┌────────────────────┐
│   Local SQLite  │                  │   PostgreSQL       │
│   (Encrypted)   │                  │   (Messages 7 days)│
└─────────────────┘                  └────────────────────┘

Key Features

    Zero-Knowledge Architecture: Server never has access to decrypted message content

    JWT Authentication: Secure token-based authentication system

    Temporary Message Storage: Messages automatically purged after 7 days

    Public Key Infrastructure: Secure exchange of encryption keys

    RESTful API: Clean, well-documented endpoints for easy integration

Technology Stack

    Framework: FastAPI with Python 3.10+

    Database: PostgreSQL with SQLAlchemy ORM

    Authentication: JWT tokens with OAuth2 password flow

    Security: BCrypt password hashing, HTTPS enforcement

    Deployment: Docker container ready with Uvicorn ASGI server

API Endpoints
Authentication

    POST /register - Create new user account

    POST /login - Obtain authentication token

    GET /me - Get current user information

Messages

    POST /messages - Send encrypted message to recipient

    GET /messages - Retrieve undelivered messages

    PUT /messages/{id}/delivered - Confirm message delivery

Key Management

    GET /public-key/{user_id} - Retrieve user's public key

    PUT /update-key - Update user's public key

Data Flow

    Registration: User creates account with public key

    Authentication: User logs in to receive JWT token

    Message Send: Client encrypts message and sends to server

    Message Retrieval: Client periodically checks for new messages

    Delivery Confirmation: Client confirms receipt to allow server cleanup

Security Model

    All messages encrypted client-side before transmission

    Server stores messages for limited time (7 days)

    Passwords hashed with BCrypt (12 rounds)

    JWT tokens expire after 30 minutes

    Rate limiting on authentication endpoints

    CORS configured for specific origins

Deployment
bash

# Environment variables
SECRET_KEY=your-super-secret-jwt-key
DATABASE_URL=postgresql://user:pass@host:port/dbname

# Run with Docker
docker build -t messenger-api .
docker run -p 8000:8000 --env-file .env messenger-api

Development Setup
bash

# Install dependencies
pip install -r requirements.txt

# Setup database
alembic upgrade head

# Run development server
uvicorn main:app --reload --host 0.0.0.0 --port 8000

