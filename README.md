WebAuthn Demo
A simple demonstration of WebAuthn (Web Authentication) implementation, allowing users to register and authenticate using platform authenticators (biometric authentication, PIN, etc.) instead of passwords.
Features

User registration with WebAuthn credentials
Passwordless authentication
Support for platform authenticators (TouchID, FaceID, Windows Hello)
Detailed debug logging for understanding WebAuthn flow
Pure JavaScript implementation (no external libraries)
Simple Flask backend
Cross-Origin Resource Sharing (CORS) support

Prerequisites

Python 3.7+
Modern browser with WebAuthn support (Chrome, Firefox, Safari, Edge)
Platform authenticator enabled on your device

Installation

Clone the repository:

bashCopygit clone https://github.com/yourusername/webauthn-demo.git
cd webauthn-demo

Install dependencies:

bashCopypip install flask flask-cors
Running the Demo

Start the Flask server:

bashCopypython PWA_server.py

Open index.html in your browser or serve it using a local HTTP server
The server will run on http://localhost:8080

Usage

Registration:

Enter a username
Click "Register"
Follow your platform's authentication prompts
Watch the debug console for detailed protocol flow


Authentication:

Enter your registered username
Click "Login"
Verify using your platform authenticator
Check the server logs for authentication flow details



Technical Details
Backend (PWA_server.py)

Flask server handling WebAuthn registration and authentication
Implements challenge generation and verification
Stores user credentials in memory (for demo purposes)
Includes detailed logging of the WebAuthn protocol flow

Frontend (index.html)

Pure JavaScript implementation of WebAuthn client
Uses Web Authentication API (navigator.credentials)
Includes console logging for debugging
Simple UI for demonstration purposes

Security Notes

This is a demonstration implementation and should not be used in production without proper security hardening
User credentials are stored in memory and will be lost when the server restarts
The implementation uses 'none' attestation for simplicity
No database persistence is implemented

Debug Information
Both frontend and backend provide detailed logging:

Frontend: Check browser console for WebAuthn API calls and responses
Backend: Server logs show the complete authentication flow

Browser Support

Chrome 67+
Firefox 60+
Safari 13+
Edge 18+

Contributing
Feel free to submit issues and enhancement requests!
References

WebAuthn Specification
MDN Web Authentication API

License
MIT License - feel free to use this demo code for learning and development purposes.

Note: This is a demonstration project intended for educational purposes. For production use, please implement proper security measures, data persistence, and error handling.
