import { NextFunction, Request, Response } from "express";

import authService from "./auth.service";
import { SuccessCreatedResponse } from "src/common/utils";
import { AUTH_MESSAGE_CONSTANT } from "src/common/constants";
import { IAuthSignup } from "src/common/interfaces";
import { catchAsyncHandler } from "src/helpers";

export class AuthController {
  async signup(req: Request, res: Response, next: NextFunction): Promise<Response> {
    const user = await authService.signup(req.body);
    return new SuccessCreatedResponse<IAuthSignup>(AUTH_MESSAGE_CONSTANT.USER_CREATED_SUCCESSFULLY, user).sendResponse(res);
  }
}

export default {
  signup: catchAsyncHandler(new AuthController().signup)
};
