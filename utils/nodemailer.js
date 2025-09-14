import nodemailer from "nodemailer";
import ejs from "ejs";
import path from "path";

export async function sendEmail({ to, name, otp }) {
  // Compile template
  const templatePath = path.join(process.cwd(),"utils","otp-template.ejs");
  const htmlContent = await ejs.renderFile(templatePath, {
    name,
    OTP: otp,
    appName: process.env.APP_NAME,
    expiryMinutes: 10,
    supportEmail: "noreply.unimart@gmail.com",
    year: new Date().getFullYear(),
  });

  // Nodemailer transporter
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  // Send mail
  await transporter.sendMail({
    from: `"${process.env.APP_NAME}" <${process.env.SMTP_USER}>`,
    to,
    subject: `${process.env.APP_NAME} — Your OTP Code`,
    html: htmlContent,
    text: `Hi ${name}, your OTP is ${otp}. It expires in 10 minutes.`,
  });
}
