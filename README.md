# Secure FinTech Application

A cybersecurity-focused mini banking application developed for CY4053 - Cybersecurity for FinTech assignment.

## Features

### Security Features Implemented

1. **User Registration & Login**
   - Secure password hashing using PBKDF2-SHA256
   - Username and email uniqueness validation
   - Session-based authentication

2. **Password Validation**
   - Minimum 8 characters
   - Must contain uppercase and lowercase letters
   - Must contain at least one digit
   - Must contain at least one special character

3. **Input Forms & Validation**
   - SQL Injection prevention using parameterized queries
   - XSS prevention through input sanitization
   - Email format validation
   - Numeric field validation
   - Input length restrictions (max 500 characters)

4. **Session Management**
   - Automatic session expiry after 5 minutes of inactivity
   - Secure session destruction on logout
   - Session-based access control

5. **Data Storage Layer**
   - Passwords stored as hashes (never in plaintext)
   - Sensitive data encrypted using Fernet symmetric encryption
   - SQLite database with proper foreign key constraints

6. **Error Handling**
   - Generic error messages (no stack traces exposed)
   - Custom error handlers for 404, 500, and 413 errors
   - Secure error logging

7. **Encryption/Decryption**
   - Fernet encryption for sensitive data
   - Encryption key management
   - Utility page for encrypt/decrypt operations

8. **Audit/Activity Logs**
   - Comprehensive activity logging
   - IP address tracking
   - Timestamp recording for all user actions

9. **Profile Update Page**
   - Secure profile data update
   - Encrypted storage of personal information
   - Input validation and sanitization

10. **File Upload Validation**
    - File type restriction (txt, pdf, png, jpg, jpeg, gif, doc, docx)
    - File size limit (16MB)
    - Secure filename handling
    - Upload activity logging

## Installation

1. Clone the repository or extract the source code

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Access the application at: `http://localhost:5000`

## Project Structure

```
Cyber Assignment/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── fintech.db            # SQLite database (created automatically)
├── encryption.key        # Encryption key (created automatically)
├── templates/            # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── transaction.html
│   ├── profile.html
│   ├── encrypt_decrypt.html
│   ├── audit_logs.html
│   ├── upload.html
│   └── error.html
├── static/               # Static files
│   ├── css/
│   │   └── style.css
│   └── js/
└── uploads/              # File uploads directory (created automatically)
```

## Usage

1. **Registration**: Create a new account with a strong password
2. **Login**: Authenticate using your credentials
3. **Dashboard**: View account balance and recent transactions
4. **Transactions**: Create deposits or withdrawals
5. **Profile**: Update personal information (encrypted)
6. **Encrypt/Decrypt**: Use encryption utility
7. **Audit Logs**: View activity history
8. **File Upload**: Securely upload files with validation

## Security Features Demonstrated

- **SQL Injection Prevention**: Parameterized queries
- **XSS Prevention**: Input sanitization
- **Password Security**: PBKDF2 hashing with salt
- **Data Encryption**: Fernet symmetric encryption
- **Session Security**: Timeout and proper cleanup
- **Access Control**: Login required decorators
- **Error Handling**: No sensitive information leakage
- **Audit Trail**: Comprehensive activity logging

## Testing

The application includes 20+ manual test cases for cybersecurity testing. Refer to the test case documentation for detailed test scenarios.

## Database Schema

- **users**: Stores user credentials (username, email, password_hash)
- **transactions**: Stores encrypted transaction data
- **audit_logs**: Activity logs with timestamps and IP addresses
- **user_profiles**: Encrypted profile information

## Technologies Used

- Python 3.x
- Flask (Web Framework)
- SQLite (Database)
- Cryptography (Fernet encryption)
- Werkzeug (Password hashing)
- Bootstrap 5 (UI Framework)

## Developer

Created for CY4053 - Cybersecurity for FinTech Assignment 2

## License

Educational use only

