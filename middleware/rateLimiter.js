// middlewares/rateLimiter.js
import rateLimit from 'express-rate-limit';

// OTP rate limiter middleware (5 requests per 15 minutes)
export const otpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 requests per IP address in this period
  message: 'Too many OTP requests, please try again after 15 minutes.',
  standardHeaders: true, // Include rate limit info in response headers
  legacyHeaders: false, // Disable 'X-RateLimit-*' headers
});

// Password login rate limiter middleware (3 attempts per 10 minutes)
export const passwordLoginRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 3, // Limit to 3 requests per IP address in this period
  message: 'Too many login attempts, please try again after 10 minutes.',
  standardHeaders: true,
  legacyHeaders: false,
});
