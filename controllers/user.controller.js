import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

import User from '../models/user.model.js';
import { EmailVerification } from '../models/emailVerify.model.js';
import { Passwords } from '../models/passwords.model.js';
import { UserRefreshToken } from '../models/UserRefreshToken.model.js';
import { CloudinaryUpload } from "../services/cloudinary.js"
import { sendEmail } from '../services/emailService.js';
import { generateOTP, generateAccessToken, generateRefreshToken , setTokenCookies , isTokenExpired} from '../utils/tokenUtils.js';
import { ENV_VARS } from '../config/envVars.js';
import logger from "../utils/logger.js";
import { v4 as uuidv4 } from "uuid"; 
import mongoose from 'mongoose';

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
  
  // Update profile controller
  export const updateProfile = async (req, res) => {
    const { name, username, phone } = req.body;
    const userId = req.user._id; 


    console.log(req.body);
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      // Initialize variables to hold updates
      let updatedFields = {};
  
      // Validate new username
      if (username && username !== user.username) {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
          return res.status(400).json({ message: "Username already exists" });
        }
        updatedFields.username = username;
      }
  
  
      // Prepare other field updates
      if (name) updatedFields.name = name;
      if (phone) updatedFields.phone = phone;
  
      
  
      // Update the user document only after all checks are passed
      Object.assign(user, updatedFields);
      await user.save();
  
      return res.status(200).json({
        message:"Profile updated successfully.",
        user,
      });
    } catch (error) {
      logger.error('Profile update error: ' + error.message);
      return res.status(500).json({ message: "Server error during profile update" });
    }
  };
  
  
// Update profile picture controller  
export const updateProfilePic = async (req, res) => {
    const userId = req.user._id;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      if (req.file) {
        const folder = "profile_pictures"; // Folder in Cloudinary
        const response = await CloudinaryUpload(req.file, folder, user.username); // Use username as the filename
        user.profilePic = response.secure_url; // Get the secure URL from Cloudinary response
      } else {
        return res.status(400).json({ message: "Profile picture is required" });
      }
  
      await user.save();
  
      return res.status(200).json({ message: "Profile picture updated successfully", user });
    } catch (error) {
      logger.error('Profile picture update error: ' + error.message);
      return res.status(500).json({ message: "Server error during profile picture update" });
    }
  };
  
  // Delete profile picture controller // TODO: check this
  export const deleteProfilePic = async (req, res) => {
    const userId = req.user._id;
  
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      user.profilePic = "https://res.cloudinary.com/du9jzqlpt/image/upload/v1674647316/avatar_drzgxv.jpg"; // Default profile picture
      await user.save();
  
      return res.status(200).json({ message: "Profile picture deleted successfully", user });
    } catch (error) {
      logger.error('Profile picture delete error: ' + error.message);
      return res.status(500).json({ message: "Server error during profile picture delete" });
    }
  };
  
  // Delete account controller // TODO: check this
  export const deleteAccount = async (req, res) => {
    const userId = req.user._id;
  
    const session = await mongoose.startSession();
    session.startTransaction();
  
    try {
      const user = await User.findById(userId).session(session);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      await User.findByIdAndDelete(userId).session(session);
      await UserRefreshToken.deleteMany({ userId: userId }).session(session);
      await Passwords.deleteMany({ userId: userId }).session(session);
      await EmailVerification.deleteMany({ userId: userId }).session(session);

      await session.commitTransaction();
      session.endSession();
  
      return res.status(200).json({ message: "Account deleted successfully" });
    } catch (error) {
      await session.abortTransaction(); 
      session.endSession();
      logger.error('Account delete error: ' + error.message);
      return res.status(500).json({ message: "Server error during account delete" });
    }
};
  

  export const resendEmailVerification = async (req, res) => {
    try {
      const user = req.user; // The user is already attached by the `verifyAccessToken` middleware
  
      // Check if email is already verified
      if (user.emailVerified) {
        return res.status(400).json({ message: "Email is already verified" });
      }
  
      // Generate a new email verification token
      const emailVerificationToken = jwt.sign(
        { userId: user.email },
        ENV_VARS.JWT_SECRET,
        { expiresIn: "15m" } // Token expires in 15 minutes
      );
  
      // Update the user with the new token and expiration time
      user.emailVerificationToken = emailVerificationToken;
      user.verificationExpires = Date.now() + 15 * 60 * 1000; // Set new expiration time
      await user.save();
  
      // Create the verification URL
      const verificationUrl = `${ENV_VARS.FRONTEND_URL}/verify-email/${emailVerificationToken}`;
  
      // Send the verification email
      await sendEmail(
        user.email,
        'Email Verification',
        'emailVerification',
        { verificationUrl }
      );
  
      return res.status(200).json({
        message: "A new verification email has been sent. Please check your inbox.",
      });
    } catch (error) {
      logger.error("Resend email verification error: " + error.message);
      return res.status(500).json({ message: "Server error while resending verification email" });
    }
  };