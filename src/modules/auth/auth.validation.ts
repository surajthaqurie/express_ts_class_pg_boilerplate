import Joi from "joi";
import { IAuthSignupPayload } from "src/common/interfaces";

export const signupValidation = (data: IAuthSignupPayload): Joi.ValidationResult<IAuthSignupPayload> => {
  const schema = Joi.object<IAuthSignupPayload, true>({
    firstName: Joi.string().trim().required(),
    lastName: Joi.string().trim().required(),
    username: Joi.string().trim().required(),
    phone: Joi.string().trim().required(),
    email: Joi.string().lowercase().email().trim().required(),
    password: Joi.string()
      /* .regex(/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$/) */
      .trim()
      .required(),
    confirmPassword: Joi.string().trim().required()
  });

  return schema.validate(data);
};
