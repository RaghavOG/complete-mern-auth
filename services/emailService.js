import nodemailer from 'nodemailer';
import ejs from 'ejs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ENV_VARS } from '../config/envVars.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const templateMapping = {
  emailVerification: path.join(__dirname, 'templates', 'emailVerification.html'),
  loginOtp: path.join(__dirname, 'templates', 'loginOtp.html'),
  passwordReset: path.join(__dirname, 'templates', 'passwordReset.html'),
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: ENV_VARS.EMAIL_USER,
    pass: ENV_VARS.EMAIL_PASS
  }
});

const renderTemplate = (templatePath, data) => {
  return new Promise((resolve, reject) => {
    ejs.renderFile(templatePath, data, (err, str) => {
      if (err) {
        reject(err);
      } else {
        resolve(str);
      }
    });
  });
};



export const sendEmail = async (to, subject, emailType, data) => {
  const templatePath = templateMapping[emailType];
  if (!templatePath) {
    throw new Error(`Invalid email type: ${emailType}`);
  }

  const html = await renderTemplate(templatePath, data);

  const mailOptions = {
    from: ENV_VARS.EMAIL_USER,
    to,
    subject,
    html
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
};

