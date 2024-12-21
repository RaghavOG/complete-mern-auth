# Auth Controller Documentation

## Overview

The Auth Controller handles user authentication, including signup, login, logout, email verification, OTP-based login, password management, and token management. Each function is designed to ensure secure and efficient user authentication and management.

## Features

- User Registration and Login
- Email Verification
- Login with OTP
- Login with Password
- Login with OTP and Password
- Password Management
- Token Management
- Profile Management
- Secure Authentication
- Profile Picture Management

- And many more ...

## Getting Started

### Prerequisites

- Node.js
- npm (Node Package Manager)
- MongoDB

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/RaghavOG/auth-controller.git
   cd auth-controller
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Set up environment variables:**

   Create a `.env` file in the root directory and add the following variables:

   ```env
   PORT=7000
   MONGO_URI=<YOUR MONGODB URL>
   FRONTEND_URL=http://localhost:5173
   EMAIL_USER=<YOUR EMAIL ADDRESS>
   EMAIL_PASS=<YOUR EMAIL APP PASSWORD>
   NODE_ENV=development
   JWT_SECRET=your_jwt_secret
   JWT_REFRESH_SECRET=your_jwt_refresh_secret
   CLOUDINARY_NAME=<YOUR CLOUDINARY NAME>
   CLOUDINARY_API_KEY=<YOUR CLOUDINARY API KEY>
   CLOUDINARY_API_SECRET=<YOUR CLOUDINARY SECRET>
   ```

### Running the Project

1. **Start the server:**

   ```bash
   npm start
   ```

2. **Access the application:**

   Open your browser and navigate to `http://localhost:5173` to access the frontend.

## Functions

### 1. Signup

**Route:** `POST /signup`

**Description:** Registers a new user with the provided details.

**Request Body:**
```json
{
  "name": "string",
  "username": "string",
  "email": "string",
  "phone": "string",
  "password": "string",
  "confirmPassword": "string"
}
```

**Response:**
- **201 Created:** User registered successfully.
- **400 Bad Request:** Validation errors (e.g., passwords do not match, user already exists).
- **500 Internal Server Error:** Server error during signup.

**Functionality:**
- Validates password match.
- Checks if the user already exists.
- Uploads profile picture to Cloudinary.
- Hashes the password.
- Generates an email verification token.
- Saves the user and password history.
- Sends a verification email.

### 2. Login

**Route:** `POST /login`

**Description:** Logs in a user with email and password.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- **200 OK:** Login successful.
- **400 Bad Request:** Invalid credentials.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error during login.

**Functionality:**
- Finds the user by email.
- Checks for account lockout.
- Verifies the password.
- Manages failed login attempts.
- Generates session ID and tokens.
- Sets cookies for access and refresh tokens.

### 3. Logout

**Route:** `POST /logout`

**Description:** Logs out the user from the current session.

**Response:**
- **200 OK:** Logged out successfully.
- **400 Bad Request:** No refresh token provided.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during logout.

**Functionality:**
- Finds and removes the current session.
- Blacklists the refresh token.
- Clears cookies.

### 4. Logout All Sessions

**Route:** `POST /logout-all`

**Description:** Logs out the user from all sessions.

**Response:**
- **200 OK:** Logged out from all sessions successfully.
- **400 Bad Request:** No refresh token provided.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during logout from all sessions.

**Functionality:**
- Removes all active sessions.
- Blacklists all refresh tokens.
- Clears cookies.

### 5. Refresh Access Token

**Route:** `POST /refresh-token`

**Description:** Refreshes the access token using the refresh token.

**Response:**
- **200 OK:** Tokens refreshed successfully.
- **400 Bad Request:** No refresh token provided.
- **401 Unauthorized:** Refresh token is blacklisted or not found.
- **401 Unauthorized:** Refresh token expired.
- **500 Internal Server Error:** Server error during token refresh.

**Functionality:**
- Checks if the refresh token has expired.
- Decodes the refresh token.
- Blacklists the old refresh token.
- Generates new tokens.
- Sets cookies for new tokens.

### 6. Verify Email

**Route:** `POST /verify-email`

**Description:** Verifies the user's email using the verification token.

**Request Body:**
```json
{
  "token": "string"
}
```

**Response:**
- **200 OK:** Email verified successfully.
- **400 Bad Request:** Invalid or expired token.
- **500 Internal Server Error:** Server error during email verification.

**Functionality:**
- Decodes the token.
- Finds the user by email and token.
- Marks the email as verified.
- Clears the verification token and expiration.

### 7. Send OTP

**Route:** `POST /send-otp`

**Description:** Sends an OTP to the user's email for login.

**Request Body:**
```json
{
  "email": "string"
}
```

**Response:**
- **200 OK:** OTP sent to your email.
- **400 Bad Request:** User not found.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error while sending OTP.

**Functionality:**
- Checks if the user exists.
- Checks for account lockout.
- Generates OTP and sets expiration.
- Sends OTP to the user's email.

### 8. OTP Login

**Route:** `POST /login-otp`

**Description:** Logs in the user using the OTP.

**Request Body:**
```json
{
  "email": "string",
  "otp": "string"
}
```

**Response:**
- **200 OK:** Login successful using OTP.
- **400 Bad Request:** Invalid OTP, OTP expired, OTP already used, or user not found.
- **500 Internal Server Error:** Server error during OTP login.

**Functionality:**
- Finds the OTP record for the email.
- Checks if the OTP is valid, not expired, and not used.
- Marks the OTP as used.
- Finds the user and resets failed login attempts.
- Generates session ID and tokens.
- Sets cookies for access and refresh tokens.

### 9. Forgot Password

**Route:** `POST /forgot-password`

**Description:** Sends a password reset link to the user's email.

**Request Body:**
```json
{
  "email": "string"
}
```

**Response:**
- **200 OK:** Password reset link sent to your email.
- **400 Bad Request:** User not found.
- **500 Internal Server Error:** Server error while requesting password reset.

**Functionality:**
- Finds the user by email.
- Generates a reset token and expiration.
- Saves or updates the password record.
- Sends a password reset email.

### 10. Check Reset Token

**Route:** `GET /validate-reset-token/:resetToken`

**Description:** Validates the password reset token.

**Response:**
- **200 OK:** Reset token is valid.
- **400 Bad Request:** Invalid or expired reset token.
- **500 Internal Server Error:** Server error while validating reset token.

**Functionality:**
- Checks if the token exists and is valid.

### 11. Reset Password

**Route:** `POST /reset-password`

**Description:** Resets the user's password using the reset token.

**Request Body:**
```json
{
  "resetToken": "string",
  "newPassword": "string",
  "confirmPassword": "string"
}
```

**Response:**
- **200 OK:** Password reset successfully.
- **400 Bad Request:** Invalid or expired reset token, passwords do not match, or new password contains sensitive information.
- **500 Internal Server Error:** Server error while resetting password.

**Functionality:**
- Checks if the token exists and is not used/expired.
- Finds the user by the token.
- Validates the new password.
- Hashes the new password.
- Updates the user's password and password record.

### 12. Login Using Password and OTP

**Route:** `POST /loginUsingpasswordandotp`

**Description:** Logs in the user using password and sends an OTP for verification.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- **200 OK:** OTP sent to your email.
- **400 Bad Request:** User not found.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error during login.

**Functionality:**
- Finds the user by email.
- Checks for account lockout.
- Checks the password.
- Generates OTP and sets expiration.
- Sends OTP to the user's email.

### 13. Change Password

**Route:** `POST /change-password`

**Description:** Changes the user's password when logged in.

**Request Body:**
```json
{
  "currentPassword": "string",
  "newPassword": "string"
}
```

**Response:**
- **200 OK:** Password changed successfully.
- **400 Bad Request:** Incorrect current password, new password matches old passwords, or new password contains sensitive information.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during password change.

**Functionality:**
- Finds the user by ID.
- Verifies the current password.
- Validates the new password.
- Hashes the new password.
- Updates the user's password and password record.

### 14. Update Profile

**Route:** `PUT /update-profile`

**Description:** Updates the user's profile information.

**Request Body:**
```json
{
  "name": "string",
  "username": "string",
  "phone": "string"
}
```

**Response:**
- **200 OK:** Profile updated successfully.
- **400 Bad Request:** Username already exists.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during profile update.

**Functionality:**
- Finds the user by ID.
- Validates and updates the profile information.

### 15. Update Profile Picture

**Route:** `PUT /update-profile-pic`

**Description:** Updates the user's profile picture.

**Response:**
- **200 OK:** Profile picture updated successfully.
- **400 Bad Request:** Profile picture is required.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during profile picture update.

**Functionality:**
- Finds the user by ID.
- Uploads the profile picture to Cloudinary.
- Updates the user's profile picture.

### 16. Delete Profile Picture

**Route:** `DELETE /delete-profile-pic`

**Description:** Deletes the user's profile picture.

**Response:**
- **200 OK:** Profile picture deleted successfully.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during profile picture delete.

**Functionality:**
- Finds the user by ID.
- Sets the profile picture to the default picture.

### 17. Delete Account

**Route:** `DELETE /delete-account`

**Description:** Deletes the user's account.

**Response:**
- **200 OK:** Account deleted successfully.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during account delete.

**Functionality:**
- Finds the user by ID.
- Deletes the user and related records.

### 18. Resend Email Verification

**Route:** `POST /resend-email-verification`

**Description:** Resends the email verification link to the user.

**Response:**
- **200 OK:** A new verification email has been sent.
- **400 Bad Request:** Email is already verified.
- **500 Internal Server Error:** Server error while resending verification email.

**Functionality:**
- Checks if the email is already verified.
- Generates a new email verification token.
- Updates the user with the new token and expiration time.
- Sends the verification email.

## Routes

### 1. Protected Route

**Route:** `GET /protected`

**Description:** A protected route that requires authentication.

**Response:**
- **200 OK:** Access granted.
- **401 Unauthorized:** Access denied.

**Functionality:**
- Verifies the access token.
- Returns the user information.

### 2. Signup

**Route:** `POST /signup`

**Description:** Registers a new user.

**Request Body:**
```json
{
  "name": "string",
  "username": "string",
  "email": "string",
  "phone": "string",
  "password": "string",
  "confirmPassword": "string"
}
```

**Response:**
- **201 Created:** User registered successfully.
- **400 Bad Request:** Validation errors.
- **500 Internal Server Error:** Server error during signup.

### 3. Login

**Route:** `POST /login`

**Description:** Logs in a user with email and password.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- **200 OK:** Login successful.
- **400 Bad Request:** Invalid credentials.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error during login.

### 4. Logout

**Route:** `POST /logout`

**Description:** Logs out the user from the current session.

**Response:**
- **200 OK:** Logged out successfully.
- **400 Bad Request:** No refresh token provided.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during logout.

### 5. Logout All Sessions

**Route:** `POST /logout-all`

**Description:** Logs out the user from all sessions.

**Response:**
- **200 OK:** Logged out from all sessions successfully.
- **400 Bad Request:** No refresh token provided.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during logout from all sessions.

### 6. Login Using Password and OTP

**Route:** `POST /loginUsingpasswordandotp`

**Description:** Logs in the user using password and sends an OTP for verification.

**Request Body:**
```json
{
  "email": "string",
  "password": "string"
}
```

**Response:**
- **200 OK:** OTP sent to your email.
- **400 Bad Request:** User not found.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error during login.

### 7. Verify Email

**Route:** `POST /verify-email`

**Description:** Verifies the user's email using the verification token.

**Request Body:**
```json
{
  "token": "string"
}
```

**Response:**
- **200 OK:** Email verified successfully.
- **400 Bad Request:** Invalid or expired token.
- **500 Internal Server Error:** Server error during email verification.

### 8. Resend OTP Verification

**Route:** `POST /resend-otp-verification`

**Description:** Resends the OTP for email verification.

**Response:**
- **200 OK:** OTP sent to your email.
- **400 Bad Request:** User not found.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error while sending OTP.

### 9. Refresh Access Token

**Route:** `POST /refresh-token`

**Description:** Refreshes the access token using the refresh token.

**Response:**
- **200 OK:** Tokens refreshed successfully.
- **400 Bad Request:** No refresh token provided.
- **401 Unauthorized:** Refresh token is blacklisted or not found.
- **401 Unauthorized:** Refresh token expired.
- **500 Internal Server Error:** Server error during token refresh.

### 10. Send OTP

**Route:** `POST /send-otp`

**Description:** Sends an OTP to the user's email for login.

**Request Body:**
```json
{
  "email": "string"
}
```

**Response:**
- **200 OK:** OTP sent to your email.
- **400 Bad Request:** User not found.
- **403 Forbidden:** Account is locked.
- **500 Internal Server Error:** Server error while sending OTP.

### 11. OTP Login

**Route:** `POST /login-otp`

**Description:** Logs in the user using the OTP.

**Request Body:**
```json
{
  "email": "string",
  "otp": "string"
}
```

**Response:**
- **200 OK:** Login successful using OTP.
- **400 Bad Request:** Invalid OTP, OTP expired, OTP already used, or user not found.
- **500 Internal Server Error:** Server error during OTP login.

### 12. Forgot Password

**Route:** `POST /forgot-password`

**Description:** Sends a password reset link to the user's email.

**Request Body:**
```json
{
  "email": "string"
}
```

**Response:**
- **200 OK:** Password reset link sent to your email.
- **400 Bad Request:** User not found.
- **500 Internal Server Error:** Server error while requesting password reset.

### 13. Validate Reset Token

**Route:** `GET /validate-reset-token/:resetToken`

**Description:** Validates the password reset token.

**Response:**
- **200 OK:** Reset token is valid.
- **400 Bad Request:** Invalid or expired reset token.
- **500 Internal Server Error:** Server error while validating reset token.

### 14. Reset Password

**Route:** `POST /reset-password`

**Description:** Resets the user's password using the reset token.

**Request Body:**
```json
{
  "resetToken": "string",
  "newPassword": "string",
  "confirmPassword": "string"
}
```

**Response:**
- **200 OK:** Password reset successfully.
- **400 Bad Request:** Invalid or expired reset token, passwords do not match, or new password contains sensitive information.
- **500 Internal Server Error:** Server error while resetting password.

### 15. Change Password

**Route:** `POST /change-password`

**Description:** Changes the user's password when logged in.

**Request Body:**
```json
{
  "currentPassword": "string",
  "newPassword": "string"
}
```

**Response:**
- **200 OK:** Password changed successfully.
- **400 Bad Request:** Incorrect current password, new password matches old passwords, or new password contains sensitive information.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during password change.

### 16. Update Profile

**Route:** `PUT /update-profile`

**Description:** Updates the user's profile information.

**Request Body:**
```json
{
  "name": "string",
  "username": "string",
  "phone": "string"
}
```

**Response:**
- **200 OK:** Profile updated successfully.
- **400 Bad Request:** Username already exists.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during profile update.

### 17. Update Profile Picture

**Route:** `PUT /update-profile-pic`

**Description:** Updates the user's profile picture.

**Response:**
- **200 OK:** Profile picture updated successfully.
- **400 Bad Request:** Profile picture is required.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during profile picture update.

### 18. Delete Profile Picture

**Route:** `DELETE /delete-profile-pic`

**Description:** Deletes the user's profile picture.

**Response:**
- **200 OK:** Profile picture deleted successfully.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during profile picture delete.

### 19. Delete Account

**Route:** `DELETE /delete-account`

**Description:** Deletes the user's account.

**Response:**
- **200 OK:** Account deleted successfully.
- **404 Not Found:** User not found.
- **500 Internal Server Error:** Server error during account delete.

### 20. Resend Email Verification

**Route:** `POST /resend-email-verification`

**Description:** Resends the email verification link to the user.

**Response:**
- **200 OK:** A new verification email has been sent.
- **400 Bad Request:** Email is already verified.
- **500 Internal Server Error:** Server error while resending verification email.

## Middleware

### 1. Verify Access Token

**Description:** Verifies the access token in the request.

**Usage:**
- Protected routes that require authentication.

### 2. OTP Rate Limiter

**Description:** Limits the rate of OTP requests to prevent abuse.

**Usage:**
- Routes that send OTPs.

### 3. Password Login Rate Limiter

**Description:** Limits the rate of password login attempts to prevent abuse.

**Usage:**
- Routes that handle password logins.

### 4. Multer

**Description:** Handles file uploads.

**Usage:**
- Routes that require file uploads (e.g., profile picture upload).

## Services

### 1. Cloudinary Upload

**Description:** Uploads files to Cloudinary.

**Usage:**
- Uploading profile pictures.

### 2. Email Service

**Description:** Sends emails to users.

**Usage:**
- Sending verification emails, OTPs, and password reset links.

### 3. Token Utils

**Description:** Provides utility functions for token generation and management.

**Usage:**
- Generating OTPs, access tokens, and refresh tokens.

### 4. Logger

**Description:** Logs information, warnings, and errors.

**Usage:**
- Logging various events and errors throughout the application.

## Configuration

### 1. Environment Variables

**Description:** Stores configuration variables for the application.

**Usage:**
- Storing sensitive information like JWT secrets, frontend URLs, and email service credentials.

## Models

### 1. User

**Description:** Represents a user in the system.

**Fields:**
- `name`: String
- `username`: String
- `email`: String
- `phone`: String
- `password`: String
- `profilePic`: String
- `emailVerified`: Boolean
- `emailVerificationToken`: String
- `verificationExpires`: Date
- `failedLoginAttempts`: Number
- `lockoutUntil`: Date
- `activeSessions`: Array of session details

### 2. Email Verification

**Description:** Represents email verification records.

**Fields:**
- `email`: String
- `otp`: String
- `expiresAt`: Date
- `used`: Boolean
- `user`: ObjectId (reference to User)

### 3. Passwords

**Description:** Represents password history and reset tokens.

**Fields:**
- `userId`: ObjectId (reference to User)
- `passwordHash`: String
- `prevPasswords`: Array of previous password hashes
- `resetToken`: String
- `expiresAt`: Date
- `used`: Boolean

### 4. User Refresh Token

**Description:** Represents refresh tokens for users.

**Fields:**
- `userId`: ObjectId (reference to User)
- `sessionId`: String
- `refreshToken`: String
- `ip`: String
- `blacklisted`: Boolean

## Conclusion

The Auth Controller provides a comprehensive set of functions and routes to handle user authentication, including signup, login, logout, email verification, OTP-based login, password management, and token management. Each function and route is designed to ensure secure and efficient user authentication and management.