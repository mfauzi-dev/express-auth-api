import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

async function createTransporter() {
    const testAccount = await nodemailer.createTestAccount();

    return nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure: process.env.SMTP_SECURE === "true",
        auth: {
            user: testAccount.user,
            pass: testAccount.pass,
        },
    });
}

export default createTransporter;
