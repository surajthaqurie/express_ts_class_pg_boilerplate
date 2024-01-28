import { Response } from "express";
import { ErrorType } from "../enums";
import { ConflictResponse, BadRequestResponse, InternalErrorResponse } from "./api-response";
import { env } from "../../configs";
import { API_ERROR_MESSAGE_CONSTANT } from "../constants";

export abstract class ApiError extends Error {
  constructor(public type: ErrorType, override message: string) {
    super(type);
  }

  public static handleError(err: ApiError, res: Response): Response {
    switch (err.type) {
      case ErrorType.CONFLICT_REQUEST:
        return new ConflictResponse(err.message).sendResponse(res);
      case ErrorType.BAD_REQUEST:
        return new BadRequestResponse(err.message).sendResponse(res);
      case ErrorType.INTERNAL:
        return new InternalErrorResponse(err.message).sendResponse(res);
      default: {
        let message = err.message;
        if (env.appConfig.NODE_ENV === "production") message = API_ERROR_MESSAGE_CONSTANT.INTERNAL_SERVER_ERROR;
        return new InternalErrorResponse(message).sendResponse(res);
      }
    }
  }
}

export class ConflictRequestError extends ApiError {
  constructor(message: string) {
    super(ErrorType.CONFLICT_REQUEST, message);
  }
}

export class BadRequestError extends ApiError {
  constructor(message: string) {
    super(ErrorType.BAD_REQUEST, message);
  }
}

export class InternalError extends ApiError {
  constructor(message: string) {
    super(ErrorType.INTERNAL, message);
  }
}
