import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import User from '../models/user.model.js';
import { EmailVerification } from '../models/emailVerify.model.js';
import { Passwords } from '../models/passwords.model.js';
import { OTP } from '../models/otp.model.js';
import { UserRefreshToken } from '../models/UserRefreshToken.model.js';

import { sendEmail } from '../services/emailService.js';
import { generateOTP, generateAccessToken, generateRefreshToken , setTokenCookies , isTokenExpired} from '../utils/tokenUtils.js';
import { ENV_VARS } from '../config/envVars.js';
import logger from "../utils/logger.js";
import { v4 as uuidv4 } from "uuid"; 
import mongoose from 'mongoose';

// Signup controller
export const signup = async (req, res) => {
  const { name, username, email, phone, password, confirmPassword } = req.body;

  try {
    // Validate password match
    if (password !== confirmPassword) {
      logger.error('Passwords do not match');
      return res.status(400).json({ message: "Passwords do not match" });
    }

    // Check if user exists
    const userExists = await User.findOne({ $or: [{ email }, { phone }] });
    if (userExists) {
      logger.warn('User already exists: ' + email);
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new user
    const user = new User({
      name,
      username,
      email,
      phone,
      password: hashedPassword,
      profilePic: "default-profile-pic-url",
      emailVerified: false,
      verificationExpires: Date.now() + 15 * 60 * 1000,  // Verification link expires in 15 minutes
    });

    await user.save();

    // Save the password hash in the Passwords schema (for password history)
    const passwordHistory = new Passwords({
      userId: user._id,
      passwordHash: hashedPassword,
      prevPasswords: [], // No previous passwords at signup
    });
    await passwordHistory.save();

    // Send verification email
    const verificationToken = jwt.sign({ userId: user._id }, ENV_VARS.JWT_SECRET, { expiresIn: '15m' });
    const verificationUrl = `${ENV_VARS.FRONTEND_URL}/verify-email/${verificationToken}`;

    await sendEmail(user.email, 'Email Verification', `Click the link to verify your email: ${verificationUrl}`);

    logger.info(`User registered: ${user.email}`);
    return res.status(201).json({ message: "User registered. Please verify your email." });
  } catch (error) {
    logger.error('Signup error: ' + error.message);
    res.status(500).json({ message: "Server error during signup" });
  }
};

// Login controller (email/password)
export const login = async (req, res) => {

  // FIXME: Add rate limiter for login requests and NEW Access id for each login request
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    // Check for account lockout
    if (user.lockoutUntil && user.lockoutUntil > Date.now()) {
      const remainingLockTime = Math.ceil((user.lockoutUntil - Date.now()) / 60000); // Minutes remaining
      const remainingTime = Math.ceil((user.lockoutUntil - Date.now()) / 1000); // Seconds remaining
      return res.status(403).json({
        message: `Account is locked. Try again after ${remainingLockTime} minute(s) or ${remainingTime} second(s).`,
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      user.failedLoginAttempts += 1;

      // Lock the account if too many failed attempts
      if (user.failedLoginAttempts >= 5) {
        user.lockoutUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
        logger.warn(`Account locked due to multiple failed attempts: ${email}`);
      }

      await user.save();
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Reset failed login attempts and lockout time on successful login
    user.failedLoginAttempts = 0;
    user.lockoutUntil = null;

    // Generate unique sessionId
    const sessionId = uuidv4();

    // Add session details
    const sessionDetails = {
      sessionId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      issuedAt: new Date(),
    };

    // Maintain a max of 3 active sessions
    if (user.activeSessions.length >= 3) {
      user.activeSessions.shift(); // Remove the oldest session
    }
    user.activeSessions.push(sessionDetails);

    await user.save();

    // Generate access token
    const accessToken = generateAccessToken({ userId: user._id, sessionId });

    // Manage refresh token
    let refreshToken;
    const existingToken = await UserRefreshToken.findOne({ userId: user._id, sessionId });

    if (existingToken) {
      // Use the existing refresh token if it's still valid
      refreshToken = existingToken.refreshToken;
      // logger.info(`Existing refresh token reused for user: ${email}`);
    } else {
      // Generate a new refresh token and store it
      refreshToken = generateRefreshToken({ userId: user._id, sessionId });
      const userRefreshToken = new UserRefreshToken({
        userId: user._id,
        sessionId,
        refreshToken,
        ip: req.ip,
      });
      await userRefreshToken.save();
      // logger.info(`New refresh token stored for user: ${email}`);
    }

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);
    // logger.info(`Tokens set as cookies for user: ${email}`);

    // Respond with tokens
    return res.status(200).json({
      message: "Login successful",
      isAuth: true,
      data: { accessToken, refreshToken },
    });
  } catch (error) {
    logger.error("Login error: " + error.message);
    return res.status(500).json({ message: "Server error during login" });
  }
};


// Logout controller (current session)
export const logout = async (req, res) => {
  const { refreshToken } = req.cookies;

  console.log("Entered logout controller");

  console.log("==============================================")
  
  console.log(refreshToken);
  
  console.log("==============================================")
  if (!refreshToken) {
    return res.status(400).json({ message: "No refresh token provided" });
  }
  
  try {
    console.log("Entered try block");
    console.log(req.user);
    const user = await User.findOne({ _id: req.user._id });
    console.log(user);
    console.log("==============================================")
    if (!user) return res.status(404).json({ message: "User not found" });

    // Find and remove the current session
    const currentSessionIndex = user.activeSessions.findIndex(
      (session) =>
        session.ip === req.ip &&
        session.userAgent === req.headers["user-agent"]
    );

    if (currentSessionIndex > -1) {
      user.activeSessions.splice(currentSessionIndex, 1); // Remove the session
      await user.save();
      // logger.info(`Session removed for user: ${req.user.email}`);
    } else {
      logger.warn(`No matching session found for user: ${req.user.email}`);
    }

    // Blacklist refresh token
    const tokenEntry = await UserRefreshToken.findOne({ refreshToken });
    if (tokenEntry) {
      tokenEntry.blacklisted = true;
      await tokenEntry.save();
      // logger.info(`Blacklisted refresh token for user: ${tokenEntry.userId}`);
    }

    // Clear cookies
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    logger.error("Logout error: " + error.message);
    res.status(500).json({ message: "Server error during logout" });
  }
};


// Logout from all sessions
export const logoutAllSessions = async (req, res) => {
  try {
    // Find the user
    const user = await User.findOne({ _id: req.user._id });

    if (!user) return res.status(404).json({ message: "User not found" });

    // Clear all active sessions for the user
    user.activeSessions = [];
    user.refreshToken = null; // Clear user-specific refresh token if stored
    await user.save();
    logger.info(`All active sessions cleared and refresh token removed for user: ${req.user.email}`);

    // Blacklist all refresh tokens for this user
    await UserRefreshToken.updateMany(
      { userId: req.user._id },
      { blacklisted: true }
    );
    logger.info(`All refresh tokens blacklisted for user: ${req.user.email}`);

    // Clear cookies
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");

    return res.status(200).json({ message: "Logged out from all sessions successfully" });
  } catch (error) {
    logger.error("Logout all sessions error: " + error.message);
    res.status(500).json({ message: "Server error during logout from all sessions" });
  }
};


// Refresh access token
export const refreshAccessToken = async (req, res) => {
  const { refreshToken } = req.cookies;

  console.log("Refresh token: ", refreshToken);

  if (!refreshToken) return res.status(400).json({ message: "No refresh token provided" });

  try {
    // Check if the token has expired
    if (isTokenExpired(refreshToken, ENV_VARS.JWT_REFRESH_SECRET)) {
      logger.error('Refresh token expired');
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      return res.status(401).json({ message: "Refresh token expired. Please log in again." });
    }

    // Decode the refresh token to get user details
    const decoded = jwt.verify(refreshToken, ENV_VARS.JWT_REFRESH_SECRET);


    const { userId } = decoded;

    

    // Ensure userId is a valid ObjectId when querying MongoDB
    const userIdObjectId = new mongoose.Types.ObjectId(userId.userId); // Convert to ObjectId

    // Find the existing refresh token in the database
    const tokenEntry = await UserRefreshToken.findOne({ userId: userIdObjectId, refreshToken });
    if (!tokenEntry || tokenEntry.blacklisted) {
      return res.status(401).json({ message: "Refresh token is blacklisted or not found" });
    }

    // Blacklist the old refresh token (mark it as blacklisted)
    tokenEntry.blacklisted = true;
    await tokenEntry.save();

    // Generate new tokens
    const newAccessToken = generateAccessToken(userId);
    const newRefreshToken = generateRefreshToken(userId);

    // Create a new entry for the new refresh token with the current sessionId
    const newTokenEntry = new UserRefreshToken({
      userId: userIdObjectId,
      sessionId:userId.sessionId,  // Retain the same sessionId or generate a new one if necessary
      refreshToken: newRefreshToken,
      ip: req.ip,  // Optionally, save the IP address of the user
      blacklisted: false  // Mark the new refresh token as not blacklisted
    });

    // Save the new refresh token entry
    await newTokenEntry.save();

    // Set the new tokens as cookies
    setTokenCookies(res, newAccessToken, newRefreshToken);

    return res.status(200).json({ message: "Tokens refreshed successfully", isAuth: true , data:{ accessToken: newAccessToken, refreshToken: newRefreshToken } });
  } catch (error) {
    logger.error('Refresh token error: ' + error.message);
    res.status(401).json({ message: "Invalid or expired refresh token" });
  }
};
// Verify email controller
export const verifyEmail = async (req, res) => {
  const { token } = req.body;

  try {
    const decoded = jwt.verify(token, ENV_VARS.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.emailVerified) {
      logger.warn('Email verification failed: Invalid or expired token');
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    user.emailVerified = true;
    await user.save();

    // logger.info('Email verified successfully: ' + user.email);
    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    logger.error('Email verification error: ' + error.message);
    res.status(400).json({ message: "Invalid or expired token" });
  }
};

// Send OTP for login
export const sendOtp = async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn('OTP request: User not found - ' + email);
      return res.status(400).json({ message: "User not found" });
    }

    if (user.lockoutUntil && user.lockoutUntil > Date.now()) {
      const remainingLockTime = Math.ceil((user.lockoutUntil - Date.now()) / 60000); // Minutes remaining
      logger.warn(`Account is locked for user: ${email}`);
      return res.status(403).json({
        message: `Account is locked. Try again in ${remainingLockTime} minute(s).`
      });
    }

    // Generate OTP and set expiration time
    const otp = generateOTP();
    const otpExpire = Date.now() + 15 * 60 * 1000;  // OTP expires in 15 minutes

    // Find existing OTP record for this email
    // const existingOtpRecord = await EmailVerification.findOne({ email, used: false });
    
    // if (existingOtpRecord) {
    //   // Update the existing OTP record with a new OTP and expiration time
    //   existingOtpRecord.otp = otp;
    //   existingOtpRecord.expiresAt = new Date(otpExpire);
    //   existingOtpRecord.used = false; // Make sure it's marked as unused
    //   await existingOtpRecord.save();

    //   logger.info('OTP updated for user: ' + email);
    // } else {
    //   // Create a new OTP record if none exists
    //   const newOtpRecord = new EmailVerification({
    //     email,
    //     otp,
    //     expiresAt: new Date(otpExpire),
    //     used: false,
    //   });
    //   await newOtpRecord.save();

    //   logger.info('OTP created for user: ' + email);
    // }


    const otpRecord = await EmailVerification.findOneAndUpdate(
      { email }, // Search by email
      {
        otp,
        expiresAt: new Date(otpExpire),
        used: false, // Reset usage
      },
      { upsert: true, new: true } // Create new record if none exists, return updated document
    );

    logger.info(
      `OTP ${otpRecord.wasNewlyCreated ? 'created' : 'updated'} for user: ${email}`
    );




    // Send OTP to the user's email
    await sendEmail(user.email, 'Login OTP', `Your OTP for login is: ${otp}`);

    res.status(200).json({ message: "OTP sent to your email" });

  } catch (error) {
    logger.error('Error while sending OTP: ' + error.message);
    res.status(500).json({ message: "Server error while sending OTP" });
  }
};

// OTP login controller
export const otpLogin = async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: "Email and OTP are required" });
  }

  if (otp.length !== 6) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  if(!email.includes('@')){
    return res.status(400).json({ message: "Invalid Email" });
  }

  try {
    // Find OTP record for this email
    const otpRecord = await EmailVerification.findOne({ email, otp });
    if (!otpRecord) {
      logger.warn("OTP login failed: Invalid OTP for user - " + email);
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Check if OTP is expired
    if (Date.now() > otpRecord.expiresAt) {
      logger.warn("OTP login failed: OTP expired for user - " + email);
      return res.status(400).json({ message: "OTP has expired" });
    }

    // Check if OTP is already used
    if (otpRecord.used) {
      logger.warn("OTP login failed: OTP already used for user - " + email);
      return res.status(400).json({ message: "OTP already used" });
    }

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Reset failed login attempts and lockout time
    user.failedLoginAttempts = 0;
    user.lockoutUntil = null;

    // Generate unique sessionId
    const sessionId = uuidv4();

    // Add session details
    const sessionDetails = {
      sessionId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      issuedAt: new Date(),
    };

    // Maintain a max of 3 active sessions
    if (user.activeSessions.length >= 3) {
      user.activeSessions.shift(); // Remove the oldest session
    }
    user.activeSessions.push(sessionDetails);

    await user.save();

    // Generate access token
    const accessToken = generateAccessToken({ userId: user._id, sessionId });

    // Manage refresh token
    let refreshToken;
    const existingToken = await UserRefreshToken.findOne({ userId: user._id, sessionId });

    if (existingToken) {
      // Use the existing refresh token if it exists
      refreshToken = existingToken.refreshToken;
      logger.info("Using existing refresh token for user: " + user.email);
    } else {
      // Generate a new refresh token if it doesn't exist
      refreshToken = generateRefreshToken({ userId: user._id, sessionId });
      const newUserRefreshToken = new UserRefreshToken({
        userId: user._id,
        sessionId,
        refreshToken,
        ip: req.ip,
      });
      await newUserRefreshToken.save();
      logger.info("New refresh token stored for user: " + user.email);
    }

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);
    logger.info(`Tokens set as cookies for user: ${user.email}`);

    // Send response with tokens
    logger.info("User logged in via OTP: " + user.email);
    return res.status(200).json({
      message: "Login successful using OTP",
      isAuth: true,
      data: { accessToken, refreshToken },
    });
  } catch (error) {
    logger.error("OTP login error: " + error.message);
    return res.status(500).json({ message: "Server error during OTP login" });
  }
};

// Forgot password controller
export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Generate reset token and expiration
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetUrl = `${ENV_VARS.FRONTEND_URL}/reset-password/${resetToken}`;
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes expiry

    let passwordRecord = await Passwords.findOne({ userId: user._id });

    if (!passwordRecord) {
      // Create new Passwords document if none exists
      passwordRecord = new Passwords({
        userId: user._id,
        resetToken,
        expiresAt,
      });
    } else {
      // Update existing Passwords document
      passwordRecord.resetToken = resetToken;
      passwordRecord.expiresAt = expiresAt;
      passwordRecord.used = false; // Reset "used" status for a new request
    }

    await passwordRecord.save();
    await sendEmail(user.email, 'Password Reset', `Click the link to reset your password: ${resetUrl}`);

    return res.status(200).json({ message: 'Password reset link sent to your email' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ message: 'Server error while requesting password reset' });
  }
};

// Reset password controller
export const resetPassword = async (req, res) => {
  const { resetToken, newPassword, confirmPassword } = req.body;

  try {
    // Check if the token exists and is not used/expired
    const passwordRecord = await Passwords.findOne({ resetToken });
    if (!passwordRecord || passwordRecord.expiresAt < Date.now() || passwordRecord.used) {
      return res.status(400).json({ message: 'Invalid or expired reset token' });
    }

    const user = await User.findById(passwordRecord.userId);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Validate new password
    const prevPasswords = passwordRecord.prevPasswords.map((entry) => entry.passwordHash);

    // Check if the new password matches previous passwords
    let isPasswordUsed = false;
    if (prevPasswords.length > 0) {
      // Check each previous password hash against the new password
      for (const prevHash of prevPasswords) {
        if (await bcrypt.compare(newPassword, prevHash)) {
          isPasswordUsed = true;
          break;
        }
      }
    }

    // Check if the new password contains sensitive user information
    const containsSensitiveInfo = 
      newPassword.includes(user.username) || 
      newPassword.includes(user.name);

    if (isPasswordUsed || containsSensitiveInfo) {
      return res.status(400).json({
        message: 'New password cannot match old passwords or contain username/name.',
      });
    }

    // Validate password confirmation
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Save the new password in the User model
    user.password = hashedPassword;
    await user.save();

    // Update the Passwords schema
    passwordRecord.prevPasswords.push({
      passwordHash: passwordRecord.passwordHash, // Save the previous hash
      changedAt: new Date(),
    });

    if (passwordRecord.prevPasswords.length > 5) {
      passwordRecord.prevPasswords = passwordRecord.prevPasswords.slice(-5); // Keep last 5 entries
    }

    passwordRecord.passwordHash = hashedPassword;
    passwordRecord.used = true; // Mark token as used
    await passwordRecord.save();

    return res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error(error.message);
    return res.status(500).json({ message: 'Server error while resetting password' });
  }
};


// Change password controller
export const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    // Find the user by their ID

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify the current password
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      logger.warn(`Change password failed: Incorrect current password for user - ${user.email}`);
      return res.status(400).json({ message: 'Incorrect current password' });
    }

    // Fetch the user's password record
    const passwordRecord = await Passwords.findOne({ userId: user._id });
    if (!passwordRecord) {
      return res.status(404).json({ message: 'Password record not found' });
    }

    // Check against previous passwords
    const prevPasswords = passwordRecord.prevPasswords.map((entry) => entry.passwordHash);
    let isPasswordUsed = false;
    if (prevPasswords.length > 0) {
      for (const prevHash of prevPasswords) {
        if (await bcrypt.compare(newPassword, prevHash)) {
          isPasswordUsed = true;
          break;
        }
      }
    }

    // Check if the new password contains sensitive user information
    const containsSensitiveInfo =
      newPassword.includes(user.username) ||
      newPassword.includes(user.name);

    if (isPasswordUsed || containsSensitiveInfo) {
      logger.warn(`New password cannot be same as old or contain username or name for user - ${user.email}`);
      return res.status(400).json({
        message: 'New password cannot match old passwords or contain username/name.',
      });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update the user's password in the User schema
    user.password = hashedPassword;
    await user.save();

    // Update the password record in the Passwords schema
    passwordRecord.prevPasswords.push({
      passwordHash: passwordRecord.passwordHash, // Save the previous password hash
      changedAt: new Date(),
    });
    passwordRecord.passwordHash = hashedPassword; // Update with the new password hash

    // Retain only the last 5 passwords
    if (passwordRecord.prevPasswords.length > 5) {
      passwordRecord.prevPasswords = passwordRecord.prevPasswords.slice(-5);
    }

    await passwordRecord.save();

    logger.info(`Password changed successfully for user: ${user.email}`);
    res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    logger.error(`Change password error: ${error.message}`);
    res.status(500).json({ message: 'Server error during password change' });
  }
};

export const loginUsingPasswordAndOtp = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      logger.warn('Login request: User not found - ' + email);
      return res.status(400).json({ message: "User not found" });
    }

     // Check if the account is locked
     if (user.lockoutUntil && user.lockoutUntil > Date.now()) {
      const remainingLockTime = Math.ceil((user.lockoutUntil - Date.now()) / 60000); // Minutes remaining
      // const remainingTime = Math.ceil((user.lockoutUntil - Date.now()) / 1000);
      return res.status(403).json({
        message: `Account is locked. Try again after ${remainingLockTime}  minute(s).`,
      });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      user.failedLoginAttempts += 1;

      // Lock the account if too many failed attempts
      if (user.failedLoginAttempts >= 5) {
        user.lockoutUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes
        logger.warn(`Account locked due to multiple failed attempts: ${email}`);
      }

      await user.save();
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Reset failed login attempts
    // user.failedLoginAttempts = 0;
    // user.lockoutUntil = null;
    // await user.save();

    // Generate OTP and set expiration
    const otp = generateOTP();
    const otpExpire = Date.now() + 15 * 60 * 1000; // OTP expires in 15 minutes



    await EmailVerification.findOneAndUpdate(
      { email }, // Search by email
      { otp, expiresAt: new Date(otpExpire), used: false }, // Update fields
      { upsert: true, new: true } // Insert if not found, return the updated document
    );
    
    

    // Send OTP to email
    await sendEmail(user.email, 'Login OTP', `Your OTP for login is: ${otp}`);
    logger.info('OTP sent to user: ' + email);

    return res.status(200).json({ message: "OTP sent to your email" });
  } catch (error) {
    logger.error('Login error: ' + error.message);
    return res.status(500).json({ message: "Server error during login" });
  }
};