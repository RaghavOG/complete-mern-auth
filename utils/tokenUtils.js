import jwt from 'jsonwebtoken';
import { ENV_VARS } from '../config/envVars.js';

export const  generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
  };
  

  export const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, ENV_VARS.JWT_SECRET, { expiresIn: '1h' });
  };
  
  export const generateRefreshToken = (userId) => {
    return jwt.sign({ userId }, ENV_VARS.JWT_REFRESH_SECRET, { expiresIn: '7d' });
  };
  
  export const setTokenCookies = (res, accessToken, refreshToken) => {
    res.cookie('accessToken', accessToken, { httpOnly: true, maxAge: 3600000 }); // 1 hour
    res.cookie('refreshToken', refreshToken, { httpOnly: true, maxAge: 604800000 }); // 7 days
  };
  
  // Check if a token has expired
  export const isTokenExpired = (token, secret) => {
    try {
      jwt.verify(token, secret);
      return false; // Token is not expired
    } catch (err) {
      return true; // Token is expired
    }
  };