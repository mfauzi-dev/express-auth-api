import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { authRoute } from "./routes/auth.route.js";
import { errorMiddleware } from "./middleware/error.middleware.js";
import dotenv from "dotenv";
import { userRoute } from "./routes/user.route.js";
dotenv.config();

export const app = express();

app.use(
    cors({
        credentials: true,
        origin: "http://localhost:5173",
    })
);

app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoute);
app.use("/api", userRoute);

app.use(errorMiddleware);
