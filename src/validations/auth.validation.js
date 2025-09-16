import Joi from "joi";

const registerValidation = Joi.object({
    name: Joi.string().min(4).max(191).required(),
    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
        .max(191)
        .required()
        .messages({
            "string.email": `Email harus dalam format yang benar.`,
            "any.required": `Email wajib diisi`,
        }),
    password: Joi.string().min(4).max(25).required(),
    confirmPassword: Joi.string().min(4).max(25).required(),
});

const loginValidation = Joi.object({
    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ["com"] } })
        .max(191)
        .required()
        .messages({
            "string.email": `Email harus dalam format yang benar.`,
            "any.required": `Email wajib diisi`,
        }),
    password: Joi.string().min(4).max(25).required(),
});

export { registerValidation, loginValidation };
