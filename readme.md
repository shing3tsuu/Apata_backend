Zero-Knowledge End-to-End Encrypted Messenger - Router (server)

A secure, privacy-focused messaging server that implements zero-knowledge architecture for end-to-end encrypted communications. This server handles authentication, contact management, and message delivery while maintaining user privacy through cryptographic protocols.

🔐 Zero-Knowledge Authentication

    Cryptographic Challenge-Response: Users prove identity using ECDSA signatures without transmitting passwords

    JWT Token Management: Secure session management with configurable expiration

    Public Key Infrastructure: ECDSA for authentication, ECDH for key exchange

🛡️ End-to-End Encryption

    Forward Secrecy: Ephemeral key exchanges for each session

    Zero-Knowledge Architecture: Server never has access to private keys or plaintext messages

    Cryptographic Verification: All operations verified with digital signatures

👥 Contact Management

    User Discovery: Search and find other users by username

    Contact Requests: Send, accept, or reject contact invitations

    Status Tracking: Real-time contact status updates (pending, accepted, rejected)

💬 Secure Messaging

    Real-time Delivery: PostgreSQL LISTEN/NOTIFY for instant message delivery

    Message Polling: Long-polling endpoints for efficient message retrieval

    Delivery Receipts: ACK system for confirmed message delivery

    Offline Support: Queue messages for offline users

🏗️ Architecture
Core Components

    FastAPI: Modern, high-performance web framework

    PostgreSQL: Primary database with async support

    Redis: Caching and challenge storage

    SQLAlchemy: Async ORM for database operations

    Pydantic: Data validation and serialization

    Dishka: Dependency injection container

Security Layers

    Authentication Layer: ECDSA signatures for zero-knowledge proof

    Transport Layer: HTTPS/TLS encrypted communications

    Storage Layer: Encrypted message storage (client-side encryption)

    Key Management: Separate ECDSA (auth) and ECDH (encryption) keys

🔧 API Endpoints
Authentication (/auth)

    POST /register - Register new user with public keys

    GET /challenge/{username} - Request authentication challenge

    POST /login - Login with signed challenge

    POST /logout - Logout user

    GET /public-keys/{user_id} - Get user's public keys

    PUT /ecdsa-update-key - Update ECDSA public key

    PUT /ecdh-update-key - Update ECDH public key

    GET /me - Get current user info

Contacts (/contacts)

    GET /search-users - Search users by username

    GET /users-by-ids - Get users by IDs with contact status

    GET /get-contacts - Get user's contacts

    POST /send-contact-request - Send contact request

    GET /get-contact-requests - Get pending contact requests

    PUT /accept-contact-request - Accept contact request

    PUT /reject-contact-request - Reject contact request

Messages (/messages)

    POST /send - Send encrypted message

    GET /get-undelivered-messages - Get undelivered messages

    GET /poll - Long-poll for new messages

    POST /ack - Acknowledge message delivery

🔐 Security Implementation
Zero-Knowledge Authentication Flow

    Challenge Request: Client requests authentication challenge

    Challenge Generation: Server generates random challenge, stores hash

    Signature Creation: Client signs challenge with private ECDSA key

    Verification: Server verifies signature using client's public key

    Token Issuance: JWT token issued upon successful verification

🗄️ Database Schema
Users Table

    id: Primary key

    name: Unique username

    ecdsa_public_key: PEM-formatted ECDSA public key

    ecdh_public_key: PEM-formatted ECDH public key

ContactRequests Table

    id: Primary key

    sender_id, receiver_id: Foreign keys to users

    status: 'pending', 'accepted', 'rejected'

    created_at: Timestamp

Messages Table

    id: Primary key

    sender_id, recipient_id: Foreign keys to users

    message: Encrypted message bytes

    timestamp: Creation timestamp

    is_delivered: Delivery status

🔄 Message Flow

    Sender encrypts message using recipient's ECDH public key

    Server stores encrypted message and notifies recipient via PostgreSQL NOTIFY

    Recipient polls for messages or receives real-time notification

    Recipient decrypts message using their private ECDH key

    Recipient sends ACK to mark message as delivered

🛡️ Security Best Practices
Server Security

    Regular security updates

    Rate limiting on authentication endpoints

    Secure JWT secret management

    Database connection encryption

    Redis security configuration

Cryptographic Security

    Use strong elliptic curves (SECP384R1)

    Regular key rotation

    Secure random number generation

    Proper key storage and management

🚨 Error Handling

The API provides comprehensive error responses:

    400 Bad Request: Invalid input data

    401 Unauthorized: Authentication failures

    403 Forbidden: Authorization issues

    404 Not Found: Resource not found

    500 Internal Server Error: Server-side issues

📊 Monitoring and Logging

    Structured logging for all operations

    Health check endpoints

    Performance monitoring

    Security event auditing

🔧 Development
Code Structure

src/
├── core/          # Database and gateway layer
├── services/      # API routers and business logic
├── services/models/        # Pydantic models
├── services/routers/       # FastAPI endpoints
└── config.py      # Configuration management

🤝 Contributing

    Fork the repository

    Create feature branch (git checkout -b feature/amazing-feature)

    Commit changes (git commit -m 'Add amazing feature')

    Push to branch (git push origin feature/amazing-feature)

    Open Pull Request

⚠️ Disclaimer

This is a security-critical application. Use in production only after thorough security audit and penetration testing. The developers are not responsible for any security breaches resulting from misuse or misconfiguration.

🆘 Support

For security issues, please contact the security team directly. For technical support, open an issue in the repository.

