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
import { changePassword, deleteAccount, deleteProfilePic, resendEmailVerification, updateProfile, updateProfilePic } from "../controllers/user.controller.js";

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
router.post("/change-password",verifyAccessToken, changePassword); // Change password when logged in
router.put("/update-profile", verifyAccessToken, updateProfile); // Update user profile
router.put("/update-profile-pic", verifyAccessToken, upload.single("profilePic"), updateProfilePic);
router.delete("/delete-profile-pic", verifyAccessToken, deleteProfilePic);
router.delete("/delete-account", verifyAccessToken, deleteAccount);
router.post("/resend-email-verification", verifyAccessToken, resendEmailVerification);




export default router;

  