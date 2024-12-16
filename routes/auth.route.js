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
  changePassword,
  logoutAllSessions,
  refreshAccessToken,
  loginUsingPasswordAndOtp
} from "../controllers/auth.controller.js";
import { verifyAccessToken } from "../middleware/verifyToken.js";
import { protectRoute } from "../middleware/protectRoute.js";
import { otpRateLimiter , passwordLoginRateLimiter } from "../middleware/rateLimiter.js";

// TODO: ADD RATE LIMITER IN THE ROUTES


const router = express.Router();

router.get('/protected', verifyAccessToken, (req, res) => {
  res.status(200).json({ message: "Protected route access granted", user: req.user });
});

// Auth routes
router.post("/signup", signup);                     // User registration
router.post("/login", login);    // add rate lii                   // Email/Password login wihtout OTP
router.post("/logout",verifyAccessToken ,logout);       // Logout from current session
router.post("/logout-all", logoutAllSessions); // Logout from all sessions  // TODO: 

router.post('/loginUsingpasswordandotp', loginUsingPasswordAndOtp); // Login using OTP

// Email verification
router.post("/verify-email", verifyEmail);          // Verify user email with token
router.post("/resend-otp-verification", sendOtp); // Resend verification otp

router.post('/refresh-token', refreshAccessToken);

// OTP-based login
router.post("/send-otp", sendOtp);                  // Send OTP to email
router.post("/login-otp", otpLogin);                // Login using OTP ony without password

// Password management
router.post("/forgot-password", forgotPassword);    // Request password reset
router.post("/reset-password", resetPassword);      // Reset password via token
router.post("/change-password", protectRoute, changePassword); // Change password when logged in

export default router;
