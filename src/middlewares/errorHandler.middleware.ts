import { Prisma } from "@prisma/client";
import { ErrorRequestHandler, NextFunction, Request, Response } from "express";

import { ApiError, BadRequestResponse, ConflictResponse, InternalError } from "src/common/utils";
import { API_ERROR_MESSAGE_CONSTANT } from "src/common/constants";
import { env } from "src/configs";

export const errorHandler: ErrorRequestHandler = (err: Error, req: Request, res: Response, next: NextFunction): Response => {
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    switch (err.code) {
      case "P2002":
        let name = err.meta && err.meta.target;
        let message = `This ${name} was already taken. Please choose different ${name}.`;
        return new ConflictResponse(message).sendResponse(res);
      case "P2014":
        name = err.meta && err.meta.target;
        message = `Invalid ID: ${name}.`;
        return new BadRequestResponse(message).sendResponse(res);
      case "P2006":
        name = err.meta && err.meta.target;
        message = `The provide value for ${name} is invalid.`;
        return new BadRequestResponse(message).sendResponse(res);
      default:
        return ApiError.handleError(new InternalError(err.message), res);
    }
  }

  if (err instanceof ApiError) return ApiError.handleError(err, res);

  if (err instanceof Prisma.PrismaClientValidationError) {
    if (env.appConfig.NODE_ENV === "production") {
      // Todo: add logger when production the err.message
    }

    // auto detect process.env.NODE_ENV production or development
    return new BadRequestResponse(err.message).sendResponse(res);
  }

  // Todo: add logger when production the err.message
  if (env.appConfig.NODE_ENV === "production") return ApiError.handleError(new InternalError(API_ERROR_MESSAGE_CONSTANT.INTERNAL_SERVER_ERROR), res);

  return ApiError.handleError(new InternalError(err.message), res);
};
