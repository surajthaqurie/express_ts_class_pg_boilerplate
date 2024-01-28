import { NextFunction, Request, Response } from "express";

import authService from "./auth.service";
import { SuccessCreatedResponse } from "../../common/utils";
import { AUTH_MESSAGE_CONSTANT } from "../../common/constants";
import { IAuthSignup } from "../../common/interfaces";
// import { catchAsyncHandler } from "src/helpers";

export class AuthController {
  async signup(req: Request, res: Response, next: NextFunction): Promise<Response> {
    const user = await authService.signup(req.body);
    const successResponse = new SuccessCreatedResponse<IAuthSignup>(AUTH_MESSAGE_CONSTANT.USER_CREATED_SUCCESSFULLY, user);
    successResponse.sendResponse(res);
    return res.status(201).json({
      success: true,
      message: AUTH_MESSAGE_CONSTANT.USER_CREATED_SUCCESSFULLY,
      data: user
    });
  }
}

// export default {
//   signup: catchAsyncHandler(new AuthController().signup)
// };
