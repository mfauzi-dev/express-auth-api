import { logger } from "../config/logger.js";
import { ResponseError } from "../middleware/error.middleware.js";
import User from "../models/User.js";
import { comparePassword, hashPassword } from "../utils/bcrypt.js";
import {
    updatePasswordValidation,
    updateProfileValidation,
} from "../validations/user.validation.js";
import { validate } from "../validations/validation.js";

export const updatePassword = async (req, res) => {
    try {
        const userId = req.user.id;
        const passwordRequest = validate(updatePasswordValidation, req.body);

        if (passwordRequest.newPassword !== passwordRequest.confirmPassword) {
            throw new ResponseError(
                404,
                "New password and confirm password do not match"
            );
        }

        const user = await User.findByPk(userId);

        const isMatch = await comparePassword(
            passwordRequest.oldPassword,
            user.password
        );

        if (!isMatch) {
            throw new ResponseError(404, "Your old password is wrong");
        }

        const hashedPassword = await hashPassword(passwordRequest.newPassword);

        await User.update(
            {
                password: hashedPassword,
            },
            {
                where: {
                    id: user.id,
                },
            }
        );

        logger.info("User updated password successfully");
        return res.status(200).json({
            success: true,
            message: "Password updated successfully",
        });
    } catch (error) {
        logger.error("Failed to updated password", error);
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};

export const updateProfile = async (req, res) => {
    try {
        const userId = req.user.id;
        const profileRequest = validate(updateProfileValidation, req.body);

        const user = await User.findByPk(userId);

        await User.update(
            {
                name: profileRequest.name,
            },
            {
                where: {
                    id: user.id,
                },
            }
        );

        logger.info("User updated profile successfully");
        return res.status(200).json({
            success: true,
            message: "Profile updated successfully",
        });
    } catch (error) {
        logger.error("Failed to updated profile", error);
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};

export const getUserProfile = async (req, res) => {
    try {
        const userId = req.user.id;

        const user = await User.findByPk(userId, {
            attributes: ["id", "name", "email", "isVerified"],
        });

        logger.info("Get user profile successfully");
        return res.status(200).json({
            success: true,
            user,
        });
    } catch (error) {
        logger.error("Failed to get user profile", error);
        res.status(400).json({
            success: false,
            message: error.message,
        });
    }
};
