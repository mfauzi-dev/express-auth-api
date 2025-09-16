import {
    passwordResetRequestTemplate,
    passwordResetSuccessTemplate,
    sendWelcomeEmailTemplate,
    verificationEmailTemplate,
} from "../templates/emailTemplate.js";
import { ResponseError } from "../middleware/error.middleware.js";
import createTransporter from "../config/email.js";
import nodemailer from "nodemailer";

import dotenv from "dotenv";
dotenv.config();

export const sendVerificationEmail = async (email, verificationToken) => {
    try {
        const transporter = await createTransporter();

        const mailOptions = await transporter.sendMail({
            from: `"No Reply" <${process.env.SMTP_MAIL}>`,
            to: email,
            subject: "Verify your email",
            html: verificationEmailTemplate.replace(
                "{verificationCode}",
                verificationToken
            ),
        });

        console.log("Preview:", nodemailer.getTestMessageUrl(mailOptions));
    } catch (error) {
        throw new ResponseError(401, `Error sending verification ${error}`);
    }
};

export const sendWelcomeEmail = async (email, name) => {
    try {
        const transporter = await createTransporter();

        const mailOptions = await transporter.sendMail({
            from: `"No Reply" <${process.env.SMTP_MAIL}>`,
            to: email,
            subject: "Welcome to our company",
            html: sendWelcomeEmailTemplate.replace("{name}", name),
        });

        console.log("Preview:", nodemailer.getTestMessageUrl(mailOptions));
    } catch (error) {
        console.log(`Error sending welcome email`, error);

        throw new Error(`Error sending welcome email ${error}`);
    }
};

export const sendPasswordResetEmail = async (email, resetURL) => {
    try {
        const transporter = await createTransporter();

        const mailOptions = await transporter.sendMail({
            from: `"No Reply" <${process.env.SMTP_MAIL}>`,
            to: email,
            subject: "Reset your password",
            html: passwordResetRequestTemplate.replace("{resetURL}", resetURL),
        });

        console.log("Preview:", nodemailer.getTestMessageUrl(mailOptions));
    } catch (error) {
        console.log(`Error sending password reset email`, error);

        throw new Error(`Error sending password reset email: ${error}`);
    }
};

export const sendResetSuccessEmail = async (email) => {
    try {
        const transporter = await createTransporter();

        const mailOptions = await transporter.sendMail({
            from: `"No Reply" <${process.env.SMTP_MAIL}>`,
            to: email,
            subject: "Password Reset Successful",
            html: passwordResetSuccessTemplate,
        });

        console.log("Preview:", nodemailer.getTestMessageUrl(mailOptions));
    } catch (error) {
        console.log(`Error sending reset success email`, error);

        throw new Error(`Error sending reset success email: ${error}`);
    }
};
