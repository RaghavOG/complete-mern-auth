import express from "express";
import {
  signup,
  login,
  logout,
  verifyEmail,
  sendOtp,
  otpLogin,
  forgotPassword,
  resetPassword,
  
  logoutAllSessions,
  refreshAccessToken,
  loginUsingPasswordAndOtp,
  checkResetToken,
} from "../controllers/auth.controller.js";
import { verifyAccessToken } from "../middleware/verifyToken.js";
import { otpRateLimiter , passwordLoginRateLimiter } from "../middleware/rateLimiter.js";
import upload from "../middleware/multer.js"
import { changePassword, deleteAccount, deleteProfilePic, profile, resendEmailVerification, updateProfile, updateProfilePic } from "../controllers/user.controller.js";

import { setup2FA, verify2FA,  disable2FA , login2FAEnabled, verifyCredentials, verify2FAAndLogin } from "../controllers/2fa.controller.js";




const router = express.Router();

router.get('/protected', verifyAccessToken, (req, res) => {
  res.status(200).json({ message: "Protected route access granted", user: req.user });
});

// Auth routes
router.post("/signup", upload.single("profilePic"),signup);                     // User registration
router.post("/login",  login);    // add rate lii                   // Email/Password login wihtout OTP
router.post("/logout",verifyAccessToken ,logout);       // Logout from current session
router.post("/logout-all",verifyAccessToken , logoutAllSessions); // Logout from all sessions  

router.post('/loginUsingpasswordandotp', loginUsingPasswordAndOtp); // Login using OTP


// Email verification
router.post("/verify-email", verifyEmail);          // Verify user email with token
router.post("/resend-otp-verification", otpRateLimiter, sendOtp); // Resend verification otp
// Access token management
router.post('/refresh-token', refreshAccessToken);

// OTP-based login
router.post("/send-otp", sendOtp);                  // Send OTP to email
router.post("/login-otp", otpLogin);                // Login using OTP ony without password

// Password management
router.post("/forgot-password", forgotPassword);    // Request password reset
router.get('/validate-reset-token/:resetToken', checkResetToken); // Validate reset token
router.post("/reset-password", resetPassword);      // Reset password via token

// USER SPECIFIC ROUTES
router.get("/profile",verifyAccessToken, profile); // Change password when logged in
router.post("/change-password",verifyAccessToken, changePassword); // Change password when logged in
router.put("/update-profile", verifyAccessToken, updateProfile); // Update user profile
router.put("/update-profile-pic", verifyAccessToken, upload.single("profilePic"), updateProfilePic);
router.delete("/delete-profile-pic", verifyAccessToken, deleteProfilePic);
router.delete("/delete-account", verifyAccessToken, deleteAccount);
router.post("/resend-email-verification", verifyAccessToken, resendEmailVerification);

/**
 * 2FA routes
*/

router.post("/2fa/setup", verifyAccessToken, setup2FA); // Generate QR code for 2FA setup
router.post("/2fa/verify", verifyAccessToken, verify2FA); // Verify 2FA code during setup
router.post("/2fa/disable", verifyAccessToken, disable2FA); // Disable 2FA for the user
router.post('/loginUsing2FAEnabled', login2FAEnabled); // Login using E/P and 2FA code ( in this the user will send all three fields together)

// below is a two step process to verify credentials and then verify 2fa then login
router.post('/verify-credentials', verifyCredentials);
router.post('/verify-2fa', verify2FAAndLogin);


export default router;

  