import { logger } from "../config/logger.js";

class ResponseError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

export const errorMiddleware = async (err, req, res, next) => {
    if (!err) {
        next();
        return;
    }

    if (err instanceof ResponseError) {
        res.status(err.status)
            .json({
                errors: err.message,
            })
            .end();
    } else {
        res.status(500)
            .json({
                errors: err.message,
            })
            .end();
    }
};

export { ResponseError };
