// import { AUTH_MESSAGE_CONSTANT } from "../../../common/constants";
import { AuthController } from "../auth.controller";
import authService from "../auth.service";
import { SuccessCreatedResponse } from "src/common/utils";

import { NextFunction, Request, Response } from "express";

jest.mock("../auth.service");
// For second test case
jest.mock("src/common/utils", () => {
  const originalModule = jest.requireActual("../../../common/utils");
  return {
    ...originalModule,
    SuccessCreatedResponse: jest.fn().mockImplementation(() => ({
      sendResponse: jest.fn()
    }))
  };
});

let authController: AuthController;
beforeEach(() => {
  authController = new AuthController();
});

afterEach(() => {
  jest.clearAllMocks;
});

describe("Auth Controller.", () => {
  // it("Returns 201, when successfully signup", async () => {
  //   const mockBody = {
  //     firstName: "string",
  //     lastName: "string",
  //     username: "string",
  //     phone: "string",
  //     email: "string",
  //     password: "string",
  //     confirmPassword: "string"
  //   };

  //   const mockReq: Request = {
  //     body: mockBody
  //   } as Request;

  //   const mockRes: Response = {
  //     status: jest.fn().mockReturnThis(),
  //     json: jest.fn()
  //   } as unknown as Response; // Cast to unknown and then to Response

  //   const mockNext: NextFunction = jest.fn();

  //   const mockUser = {
  //     id: "string",
  //     firstName: mockBody.firstName,
  //     lastName: mockBody.lastName,
  //     email: mockBody.email,
  //     username: mockBody.username,
  //     phone: mockBody.phone,
  //     avatar: null,
  //     createdAt: new Date(),
  //     updatedAt: new Date()
  //   };

  //   jest.spyOn(authService, "signup").mockResolvedValueOnce(mockUser);

  //   const mockSendResponse = jest.spyOn(SuccessCreatedResponse.prototype, "sendResponse");

  //   await authController.signup(mockReq, mockRes, mockNext);

  //   // Exceptions
  //   expect(mockSendResponse).toHaveBeenCalled();
  //   expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);

  //   expect(authService.signup).toHaveBeenCalledWith(mockReq.body);
  //   expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

  //   expect(mockRes.status).toHaveBeenCalledWith(201);
  //   expect(mockRes.json).toHaveBeenCalledWith({
  //     success: true,
  //     message: AUTH_MESSAGE_CONSTANT.USER_CREATED_SUCCESSFULLY,
  //     data: mockUser
  //   });
  // });

  it("Returns 201, when successfully signup", async () => {
    const mockBody = {
      firstName: "string",
      lastName: "string",
      username: "string",
      phone: "string",
      email: "string",
      password: "string",
      confirmPassword: "string"
    };

    const mockReq: Request = {
      body: mockBody
    } as Request;

    const mockRes: Response = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    } as unknown as Response; // Cast to unknown and then to Response

    const mockNext: NextFunction = jest.fn();

    const mockUser = {
      id: "string",
      firstName: mockBody.firstName,
      lastName: mockBody.lastName,
      email: mockBody.email,
      username: mockBody.username,
      phone: mockBody.phone,
      avatar: null,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    jest.spyOn(authService, "signup").mockResolvedValueOnce(mockUser);

    const sendResponseMock = jest.fn();
    SuccessCreatedResponse.prototype.sendResponse = sendResponseMock;

    await authController.signup(mockReq, mockRes, mockNext);
    expect(authService.signup).toHaveBeenCalledWith(mockReq.body);

    expect(SuccessCreatedResponse).toHaveBeenCalledTimes(1);
    expect(sendResponseMock.mock.calls[0][0]).toBe(mockRes);
  });
});
