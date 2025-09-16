import express from "express";
import {
    getUserProfile,
    updatePassword,
    updateProfile,
} from "../controllers/user.controller.js";
import { authenticate } from "../middleware/auth.middleware.js";

const userRoute = express.Router();

userRoute.use(authenticate);

userRoute.get("/profile", getUserProfile);
userRoute.patch("/password", updatePassword);
userRoute.patch("/profile", updateProfile);

export { userRoute };
