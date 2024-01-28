import { AUTH_MESSAGE_CONSTANT } from "../../../common/constants";
import { AuthController } from "../auth.controller";
import authService from "../auth.service";
import { SuccessCreatedResponse } from "../../../common/utils";

import { NextFunction, Request, Response } from "express";

jest.mock("../auth.service");
jest.mock("../../../common/utils", () => ({
  ...jest.requireActual("../../../common/utils"),
  SuccessCreatedResponse: jest.fn()
}));

let authController: AuthController;
beforeEach(() => {
  authController = new AuthController();
});

afterEach(() => {
  jest.clearAllMocks;
});

describe("Auth Controller.", () => {
  it("Returns 200, when successfully signup", async () => {
    const mockBody = {
      firstName: "string",
      lastName: "string",
      username: "string",
      phone: "string",
      email: "string",
      password: "string",
      confirmPassword: "string"
    };

    const req: Request = {
      body: mockBody
    } as Request;

    const res: Response = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    } as unknown as Response; // Cast to unknown and then to Response
    const next: NextFunction = jest.fn();

    const userMock = {
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

    jest.spyOn(authService, "signup").mockResolvedValueOnce(userMock);
    const successCreatedResponseMock = SuccessCreatedResponse as jest.MockedClass<typeof SuccessCreatedResponse>;
    const sendResponseMock = jest.fn();
    successCreatedResponseMock.prototype.sendResponse = sendResponseMock;

    await authController.signup(req, res, next);

    expect(authService.signup).toHaveBeenCalledWith(req.body);

    expect(successCreatedResponseMock).toHaveBeenCalledTimes(1);
    expect(sendResponseMock.mock.calls[0][0]).toBe(res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      message: AUTH_MESSAGE_CONSTANT.USER_CREATED_SUCCESSFULLY,
      data: userMock
    });
  });
});
