import nodemailer from 'nodemailer';
import { ENV_VARS } from '../config/envVars.js';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: ENV_VARS.EMAIL_USER,
    pass: ENV_VARS.EMAIL_PASS
  }
});

export const sendEmail = async (to, subject, text) => {

  const mailOptions = {
    from: ENV_VARS.EMAIL_USER,
    to,
    subject,
    text
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
};

