Backend Service - Secure Messenger API
Overview

A secure FastAPI-based backend service for an end-to-end encrypted messaging platform. This service acts as a temporary message relay and authentication hub, ensuring that sensitive message content never persists on the server in readable form.
Architecture Diagram
text

Client Apps → HTTPS/TLS → FastAPI Server → PostgreSQL Database
     ↑          (JWT)          ↓               ↓
     └── Message Sync ←── Temporary Storage (7 days)

Key Features

    JWT Authentication - Secure user authentication with token-based sessions

    Temporary Message Storage - Messages are automatically purged after 7 days

    Public Key Management - Stores users' public keys for initial message exchange

    RESTful API - Clean, standardized API endpoints for all operations

    PostgreSQL Database - Relational database with proper indexing and constraints

API Endpoints
Authentication Endpoints

    POST /register - Register new user with public key

    POST /login - Authenticate user and receive JWT token

    GET /me - Get current user information

Message Endpoints

    POST /messages - Send encrypted message to recipient

    GET /messages - Retrieve undelivered messages

    PUT /messages/{id}/delivered - Confirm message delivery

Key Management Endpoints

    GET /public-key/{user_id} - Retrieve user's public key

    PUT /update-key - Update user's public key

Security Implementation

    JWT Tokens - Stateless authentication with short-lived tokens

    Password Hashing - BCrypt with proper salt and work factors

    Input Validation - Pydantic models for all request/response objects

    CORS Protection - Configured for specific origins only

    Rate Limiting - Protection against brute force attacks

Database Schema
Users Table

    id - Primary key

    name - Unique username

    hashed_password - Securely hashed password

    public_key - PEM-formatted public key

Messages Table

    id - Primary key

    sender_id - Foreign key to users

    recipient_id - Foreign key to users

    encrypted_data - Binary encrypted message content

    timestamp - Message creation time

    is_delivered - Delivery status flag

    expires_at - Automatic expiration timestamp

Deployment Considerations

    Environment Variables - All configuration through environment variables

    Docker Ready - Containerized deployment support

    Health Checks - API endpoints for service health monitoring

    Logging - Structured logging for easy debugging

    Monitoring - Prometheus metrics endpoint

Getting Started

    Set up PostgreSQL database

    Configure environment variables

    Install dependencies: pip install -r requirements.txt

    Run database migrations

    Start server: uvicorn main:app --reload