import Joi from "joi";

const updatePasswordValidation = Joi.object({
    oldPassword: Joi.string().min(4).max(25).required(),
    newPassword: Joi.string().min(4).max(25).required(),
    confirmPassword: Joi.string().min(4).max(25).required(),
});

const updateProfileValidation = Joi.object({
    name: Joi.string().min(4).max(191).required(),
});

export { updatePasswordValidation, updateProfileValidation };
