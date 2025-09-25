
# Secure-Client-Server-Messaging-System
Designed and implemented a Python-based network communication system that supports multiple client connections to a central server with secure messaging.
The project features:

Multi-Client Architecture: Server handles concurrent client connections using threading.

Encryption & Key Exchange: Secure message transfer with AES encryption and Diffie–Hellman key exchange, with fallback to a pre-shared key.

Message Integrity: Each message is hashed with SHA-256 for verification, ensuring tamper detection.

Logging System: Server logs all messages with timestamps in a JSON file, retrievable by clients on request.

Interactive Client UI: Clients can send encrypted messages, disconnect gracefully, or retrieve recent message history.

Tech Stack: Python, Sockets, AES (PyCryptodome), Diffie–Hellman Key Exchange, JSON

 Finished early - mid 2025
