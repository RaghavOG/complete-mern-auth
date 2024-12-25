import speakeasy from "speakeasy";
import qrcode from "qrcode";
import bcrypt from "bcryptjs";
import User from "../models/user.model.js";
import { UserRefreshToken } from "../models/UserRefreshToken.model.js";
import {
  generateAccessToken,
  generateRefreshToken,
  setTokenCookies,
  isTokenExpired,
} from "../utils/tokenUtils.js";
import { v4 as uuidv4 } from "uuid";
import jwt from "jsonwebtoken";
import logger from "../utils/logger.js"; // Assuming you have a logger utility

// Generate QR code for 2FA setup
export const setup2FA = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Generate a new 2FA secret
    const secret = speakeasy.generateSecret({
      name: `MERNAuth (${user.email})`,
    });

    // Store the base32 secret in the user's account
    user.twoFASecret = secret.base32;
    user.is2FAEnabled = false; // Ensure it's not enabled until verified
    await user.save();

    // Generate QR code for the user to scan
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    return res.status(200).json({
      message: "2FA setup initialized",
      qrCodeUrl,
    });
  } catch (error) {
    logger.error("Error setting up 2FA: " + error.message);
    return res
      .status(500)
      .json({ message: "Error setting up 2FA", error: error.message });
  }
};

// Verify 2FA code during setup
export const verify2FA = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("+twoFASecret");
    if (!user) return res.status(404).json({ message: "User not found" });
    const { code } = req.body;

    if (!user.twoFASecret) {
      return res.status(400).json({ message: "2FA secret not found!" });
    }

    // Verify the provided code
    const verified = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: "base32",
      token: code,
    });

    if (!verified) {
      return res.status(400).json({ message: "Invalid 2FA code" });
    }

    // 2FA code is valid, enable 2FA
    user.is2FAEnabled = true;
    await user.save();

    return res
      .status(200)
      .json({ message: "2FA successfully verified and enabled" });
  } catch (error) {
    logger.error("Error verifying 2FA code: " + error.message);
    return res
      .status(500)
      .json({ message: "Error verifying 2FA code", error: error.message });
  }
};

// Disable 2FA
export const disable2FA = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("+twoFASecret");
    if (!user) return res.status(404).json({ message: "User not found" });

    user.is2FAEnabled = false;
    user.twoFASecret = null; // Remove the secret
    await user.save();

    return res.status(200).json({ message: "2FA disabled successfully" });
  } catch (error) {
    logger.error("Error disabling 2FA: " + error.message);
    return res
      .status(500)
      .json({ message: "Error disabling 2FA", error: error.message });
  }
};

// Login with 2FA enabled (After user has set up 2FA)

/**
 * in the the user will login with email and password and 2FA code all three togetger
 */

export const login2FAEnabled = async (req, res) => {
  const { email, password, twoFACode } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email }).select("+twoFASecret");

    if (!user) return res.status(400).json({ message: "User not found" });

    // Check for account lockout
    if (user.lockoutUntil && user.lockoutUntil > Date.now()) {
      const remainingLockTime = Math.ceil(
        (user.lockoutUntil - Date.now()) / 60000
      ); // Minutes remaining
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

    // Verify 2FA code if enabled
    if (user.is2FAEnabled) {
      const is2FAValid = speakeasy.totp.verify({
        secret: user.twoFASecret,
        encoding: "base32",
        token: twoFACode,
      });

      if (!is2FAValid) {
        return res.status(401).json({ message: "Invalid 2FA code" });
      }
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
    const existingToken = await UserRefreshToken.findOne({
      userId: user._id,
      sessionId,
    });

    if (existingToken) {
      refreshToken = existingToken.refreshToken;
    } else {
      refreshToken = generateRefreshToken({ userId: user._id, sessionId });
      const userRefreshToken = new UserRefreshToken({
        userId: user._id,
        sessionId,
        refreshToken,
        ip: req.ip,
      });
      await userRefreshToken.save();
    }

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken);

    // Respond with tokens
    return res.status(200).json({
      message: "Login successful with 2FA enabled",
      isAuth: true,
      data: {
        accessToken,
        refreshToken,
        user: {
          _id: user._id,
          name: user.name,
          username: user.username,
          email: user.email,
          phone: user.phone,
          profilePic: user.profilePic,
          emailVerified: user.emailVerified,
          is2FAEnabled: user.is2FAEnabled,
        },
      },
    });
  } catch (error) {
    logger.error("Login error with 2FA: " + error.message);
    return res.status(500).json({ message: "Server error during login" });
  }
};

export const verifyCredentials = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (user.lockoutUntil && user.lockoutUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockoutUntil - Date.now()) / 1000);
      return res.status(403).json({
        message: `Account is locked. Try again after ${remainingTime} seconds.`,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockoutUntil = Date.now() + 15 * 60 * 1000;
        logger.warn(`Account locked: ${email}`);
      }
      await user.save();
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Reset failed attempts
    user.failedLoginAttempts = 0;
    user.lockoutUntil = null;
    await user.save();

    // Generate temporary token for 2FA step
    const tempToken = jwt.sign(
      { userId: user._id, step: "2fa" },
      process.env.JWT_SECRET,
      { expiresIn: "5m" }
    );

    return res.status(200).json({
      message: "Credentials verified",
      requires2FA: user.is2FAEnabled,
      tempToken,
    });
  } catch (error) {
    logger.error("Credential verification error: " + error.message);
    return res.status(500).json({ message: "Server error" });
  }
};

// Second step: Verify 2FA and complete login
export const verify2FAAndLogin = async (req, res) => {
  const { twoFACode } = req.body;

  const tempToken = req.headers.authorization?.split(" ")[1];

  if (!tempToken) {
    return res.status(400).json({ message: "JWT token is missing" });
  }

  try {
    // Verify temp token
    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    if (decoded.step !== "2fa") {
      return res.status(401).json({ message: "Invalid token" });
    }

    const user = await User.findById(decoded.userId).select("+twoFASecret");
    if (!user) return res.status(404).json({ message: "User not found" });

    console.log("User found: ", user);

    const is2FAValid = speakeasy.totp.verify({
      secret: user.twoFASecret,
      encoding: "base32",
      token: twoFACode,
    });

    console.log("2FA valid: ", is2FAValid);

    if (!is2FAValid) {
      return res.status(401).json({ message: "Invalid 2FA code" });
    }

    console.log("2FA verified");

    // Complete login process
    const sessionId = uuidv4();
    const sessionDetails = {
      sessionId,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      issuedAt: new Date(),
    };

    if (user.activeSessions.length >= 3) {
      user.activeSessions.shift();
    }
    user.activeSessions.push(sessionDetails);
    await user.save();

    const accessToken = generateAccessToken({ userId: user._id, sessionId });
    const refreshToken = generateRefreshToken({ userId: user._id, sessionId });

    await new UserRefreshToken({
      userId: user._id,
      sessionId,
      refreshToken,
      ip: req.ip,
    }).save();

    setTokenCookies(res, accessToken, refreshToken);

    return res.status(200).json({
      message: "Login successful",
      isAuth: true,
      data: {
        accessToken,
        refreshToken,
        user: {
          _id: user._id,
          name: user.name,
          username: user.username,
          email: user.email,
          phone: user.phone,
          profilePic: user.profilePic,
          emailVerified: user.emailVerified,
          is2FAEnabled: user.is2FAEnabled,
        },
      },
    });
  } catch (error) {
    logger.error("2FA verification error: " + error.message);
    return res.status(500).json({ message: "Server error" });
  }
};
