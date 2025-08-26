Backend Service - Secure Messenger API
Overview

A secure FastAPI-based backend service for an end-to-end encrypted messaging platform. This service acts as a temporary message relay with a 7-day retention policy, ensuring messages are delivered even when recipients are offline while maintaining minimal data exposure.
Architecture
Core Components

    FastAPI Application: Modern asynchronous web framework with automatic OpenAPI documentation

    PostgreSQL Database: Persistent storage for users, public keys, and temporary messages

    JWT Authentication: Secure token-based authentication system

    Modular Design: Clean separation of concerns with gateway pattern

Key Features

    Temporary message storage (7-day retention)

    User authentication and management

    Public key distribution

    Message queuing for offline recipients

    RESTful API with comprehensive error handling

Security Implementation

    HS256 JWT tokens with configurable expiration

    Password hashing using bcrypt with timing attack protection

    Secure API endpoints with dependency-based authentication

    Input validation using Pydantic models

API Endpoints

    POST /register - User registration with public key

    POST /login - User authentication

    GET /me - Current user information

    GET /public-key/{user_id} - Retrieve user's public key

    PUT /update-key - Update user's public key

    Message endpoints (to be implemented)

Database Schema

    users: User credentials and public keys

    messages: Encrypted messages with delivery status

    contacts: User contact relationships

Deployment Considerations

    Containerized with Docker

    Environment-based configuration

    PostgreSQL connection pooling

    Horizontal scaling capabilities
