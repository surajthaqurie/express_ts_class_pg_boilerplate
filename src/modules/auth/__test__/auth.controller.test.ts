/* 
import { AuthController } from "../auth.controller";
import { AuthService } from "../auth.service";
import { v4 as uuidv4 } from "uuid";

import { Request, Response, NextFunction } from "express";
import { SuccessCreatedResponse, SuccessResponse, SuccessResponseWithPagination, SuccessWithNoData } from "@sharedModule/shared";
import { AUTH_ERROR_MESSAGE, AUTH_SUCCESS_MESSAGE } from "../auth.constant";
import { logger } from "@sharedModule/chat-app";

jest.mock("../auth.service");
jest.mock("@sharedModule/chat-app");

let authController: AuthController;
let mockReq: Request;
let mockRes: Response;
let mockNext: NextFunction;

beforeEach(() => {
  authController = new AuthController();
  mockReq = {} as Request;

  mockRes = {} as Response;
  mockRes.status = jest.fn().mockReturnThis();
  mockRes.json = jest.fn();

  mockNext = jest.fn() as NextFunction;
});

afterEach(() => {
  // jest.clearAllMocks()
  jest.restoreAllMocks();
});

describe("AuthController.", () => {
  const mockUser = {
    id: uuidv4(),
    username: "garcia_101",
    email: "garcia101@yopmail.com",
    password: "hashPassword",
    fullname: "Naomi Garcia",
    phoneNumber: "1234567890",
    isDeleted: false,
    resetPasswordExpiration: new Date(),
    Profiles: {
      profilePic: "profile.png"
    }
  };

  describe("Signup.", () => {
    it("Returns 400, when unable to signup user.", async () => {
      mockReq = {
        body: {
          fullname: "Naomi Garcia",
          email: "garcia101@yopmail.com",
          password: "paSSworD#$",
          username: "garcia_101",
          phoneNumber: "1234567890",
          confirmPassword: "paSSworD#$"
        }
      } as Request;

      const mockError = new Error("Unable to signup");

      // Mocks
      jest.spyOn(AuthService.prototype, "signup").mockRejectedValueOnce(mockError);

      // Acts
      await authController.signup(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.signup).toHaveBeenCalledWith(mockReq.body);
      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_SIGNUP, mockError);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 201, when user signup successfully.", async () => {
      mockReq = {
        body: {
          fullname: "Naomi Garcia",
          email: "garcia101@yopmail.com",
          password: "paSSworD#$",
          username: "garcia_101",
          phoneNumber: "1234567890",
          confirmPassword: "paSSworD#$"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "signup").mockResolvedValueOnce(mockUser);

      const mockSendResponse = jest.spyOn(SuccessCreatedResponse.prototype, "sendResponse");

      // Acts
      await authController.signup(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);

      expect(AuthService.prototype.signup).toHaveBeenCalledWith(mockReq.body);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(201);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.SIGNUP,
        data: mockUser
      });
    });
  });

  describe("Login.", () => {
    it("Returns 400, when user is unable to login.", async () => {
      const mockError = new Error("Unable to login");

      mockReq = {
        body: {
          username: "garcia_101",
          password: "paSSworD#$"
        }
      } as Request;

      mockReq.get = jest.fn().mockReturnValue("mocked-session-id");
      mockReq.useragent = {};
      mockReq.ip = "127.0.0.1";

      const sessionId = mockReq.get("session-id") || null;
      const metadata = { ...mockReq.useragent, ipAddress: mockReq.ip };

      // Mocks
      jest.spyOn(AuthService.prototype, "login").mockRejectedValueOnce(mockError);

      // Acts
      await authController.login(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.login).toHaveBeenCalledWith(mockReq.body, sessionId, metadata);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_LOGIN, mockError);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when user login successfully.", async () => {
      mockReq = {
        body: {
          username: "garcia_101",
          password: "paSSworD#$"
        }
      } as Request;

      mockReq.get = jest.fn().mockReturnValue("mocked-session-id");
      mockReq.useragent = {};
      mockReq.ip = "127.0.0.1";

      const sessionId = mockReq.get("session-id") || null;
      const metadata = { ...mockReq.useragent, ipAddress: mockReq.ip };

      // Mocks
      jest.spyOn(AuthService.prototype, "login").mockResolvedValueOnce({
        accessToken: "mockAccessToken",
        refreshToken: "mockRefreshToken",
        user: mockUser,
        sessionId: "mockSessionId"
      });

      const mockSendResponse = jest.spyOn(SuccessResponse.prototype, "sendResponse");

      // Acts
      await authController.login(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);

      expect(AuthService.prototype.login).toHaveBeenCalledWith(mockReq.body, sessionId, metadata);

      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.LOGIN,
        data: {
          accessToken: "mockAccessToken",
          refreshToken: "mockRefreshToken",
          user: mockUser,
          sessionId: "mockSessionId"
        }
      });
    });
  });

  describe("Check Registered User.", () => {
    it("Returns 400, when unable to check registered user.", async () => {
      const mockError = new Error("Unable to check register user");

      mockReq = {
        body: {
          username: "garcia_101",
          email: "garcia101@yopmail.com",
          phoneNumber: "1234567890"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "checkRegisteredUser").mockRejectedValueOnce(mockError);

      // Acts
      await authController.checkRegisteredUser(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.checkRegisteredUser).toHaveBeenCalledWith(mockReq.body);
      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_CHECK_REGISTERED_USER, mockError);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when registered user checked successfully.", async () => {
      mockReq = {
        body: {
          username: "garcia_101",
          email: "garcia101@yopmail.com",
          phoneNumber: "1234567890"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "checkRegisteredUser").mockResolvedValueOnce({
        isRegistered: false,
        message: AUTH_SUCCESS_MESSAGE.VALIDATE_SUCCESSFULLY
      });

      const mockSendResponse = jest.spyOn(SuccessResponse.prototype, "sendResponse");

      // Acts
      await authController.checkRegisteredUser(mockReq, mockRes, mockNext);

      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.checkRegisteredUser).toHaveBeenCalledWith(mockReq.body);

      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.CHECK_USER_EXIST,
        data: {
          isRegistered: false,
          message: AUTH_SUCCESS_MESSAGE.VALIDATE_SUCCESSFULLY
        }
      });
    });
  });

  describe("Single Logout.", () => {
    it("Returns 400, when unable to logout.", async () => {
      mockReq.sessionId = "mocked-session-id";
      const mockError = new Error("Unable to Logout");

      // Mocks
      jest.spyOn(AuthService.prototype, "logout").mockRejectedValueOnce(mockError);

      // Acts
      await authController.logout(mockReq, mockRes, mockNext);

      // Executions
      expect(AuthService.prototype.logout).toHaveBeenCalledWith(mockReq.sessionId);
      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_LOGOUT, mockError);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when user logout successfully.", async () => {
      const mockResponse = {
        sessionId: mockReq.sessionId,
        userId: uuidv4()
      };
      mockReq.sessionId = "mocked-session-id";

      // Mocks
      jest.spyOn(AuthService.prototype, "logout").mockResolvedValueOnce(mockResponse);

      const mockSendResponse = jest.spyOn(SuccessResponse.prototype, "sendResponse");

      // Acts
      await authController.logout(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(AuthService.prototype.logout).toHaveBeenCalledWith(mockReq.sessionId);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.LOGOUT_SINGLE,
        data: mockResponse
      });
    });
  });

  describe("Multi logout.", () => {
    it("Returns 400, when unable to logout.", async () => {
      mockReq = {
        auth: {
          userId: "mock-user-Id"
        }
      } as Request;

      const mockError = new Error("Unable to multiple logout");

      // Mocks
      jest.spyOn(AuthService.prototype, "logoutAll").mockRejectedValueOnce(mockError);

      // Acts
      await authController.logoutAll(mockReq, mockRes, mockNext);

      // Executions
      expect(AuthService.prototype.logoutAll).toHaveBeenCalledWith(mockReq.auth.userId);
      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_MULTIPLE_LOGOUT, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when user logout from multiple devices successfully.", async () => {
      mockReq = {
        auth: {
          userId: "mock-user-Id"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "logoutAll").mockImplementationOnce(() => Promise.resolve());

      const mockSendResponse = jest.spyOn(SuccessResponse.prototype, "sendResponse");

      // Acts
      await authController.logoutAll(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(AuthService.prototype.logoutAll).toHaveBeenCalledWith(mockReq.auth.userId);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.LOGOUT_MULTIPLE
      });
    });
  });

  describe("Send Mail.", () => {
    it("Returns 401, when users opt was blocked.", async () => {
      mockReq = {
        body: {
          email: "garcia101@yopmail.com"
        }
      } as Request;

      const mockResponse = {
        blockedFeatureTime: new Date()
      };

      // Mocks
      jest.spyOn(AuthService.prototype, "sendEmail").mockResolvedValueOnce(mockResponse);

      // Acts
      await authController.sendEmail(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.sendEmail).toHaveBeenCalledWith(mockReq.body.email);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: false,
        message: AUTH_ERROR_MESSAGE.OTP_BLOCKED,
        data: mockResponse
      });
    });

    it("Returns 400, when unable to send mail.", async () => {
      const mockError = new Error("Unable to send mail");
      mockReq = {
        body: {
          email: "garcia101@yopmail.com"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "sendEmail").mockRejectedValueOnce(mockError);

      // Acts
      await authController.sendEmail(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.sendEmail).toHaveBeenCalledWith(mockReq.body.email);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_SEND_MAIL, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when mail was sent successfully.", async () => {
      mockReq = {
        body: {
          email: "garcia101@yopmail.com"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "sendEmail").mockImplementationOnce(() => Promise.resolve());

      const mockSendResponse = jest.spyOn(SuccessWithNoData.prototype, "sendResponse");

      // Acts
      await authController.sendEmail(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);

      expect(AuthService.prototype.sendEmail).toHaveBeenCalledWith(mockReq.body.email);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.SEND_EMAIL
      });
    });
  });

  describe("Reset Password.", () => {
    it("Returns 400, when unable to reset password.", async () => {
      mockReq = {
        body: {
          email: "garcia101@yopmail.com",
          newPassword: "neWPAs$word"
        }
      } as Request;

      const mockError = new Error("Something went wrong, unable to rest password");

      // Mocks
      jest.spyOn(AuthService.prototype, "resetPassword").mockRejectedValueOnce(mockError);

      // Acts
      await authController.resetPassword(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.resetPassword).toHaveBeenCalledWith(mockReq.body);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_RESET_PASSWORD, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when password was rest successfully.", async () => {
      mockReq = {
        body: {
          email: "garcia101@yopmail.com",
          newPassword: "neWPAs$word"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "resetPassword").mockImplementationOnce(() => Promise.resolve());
      const mockSendResponse = jest.spyOn(SuccessWithNoData.prototype, "sendResponse");

      // Acts
      await authController.resetPassword(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.resetPassword).toHaveBeenCalledWith(mockReq.body);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.PASSWORD_RESET
      });
    });
  });

  describe("Verify Reset Password OTP.", () => {
    it("Returns 400, when unable to verify and reset password OTP,", async () => {
      mockReq = {
        body: {
          email: "garcia101@yopmail.com",
          otp: "randomOTP"
        }
      } as Request;

      const mockError = new Error("Something went wrong, unable to verify and reset password OTP");

      // Mocks
      jest.spyOn(AuthService.prototype, "verifyResetPasswordOtp").mockRejectedValueOnce(mockError);

      // Acts
      await authController.verifyResetPasswordOtp(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.verifyResetPasswordOtp).toHaveBeenCalledWith(mockReq.body);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_RESET_PASSWORD, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when password was rest successfully.", async () => {
      mockReq = {
        body: {
          email: "garcia101@yopmail.com",
          otp: "randomOTP"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "verifyResetPasswordOtp").mockImplementationOnce(() => Promise.resolve());

      const mockSendResponse = jest.spyOn(SuccessWithNoData.prototype, "sendResponse");

      // Acts
      await authController.verifyResetPasswordOtp(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.verifyResetPasswordOtp).toHaveBeenCalledWith(mockReq.body);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.VERIFIED_PASSWORD_RESET
      });
    });
  });

  describe("Change Password.", () => {
    it("Returns 400, when unable to change password.", async () => {
      mockReq = {
        body: {
          oldPassword: "oldPassword",
          newPassword: "newPassword"
        },
        auth: {
          userId: "mock-user-id"
        }
      } as Request;

      const mockError = new Error("Something went wrong, unable to change password");

      // Mocks
      jest.spyOn(AuthService.prototype, "changePassword").mockRejectedValueOnce(mockError);

      // Acts
      await authController.changePassword(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.changePassword).toHaveBeenCalledWith(mockReq.body, mockReq.auth.userId);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_CHANGE_PASSWORD, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when password changed successfully.", async () => {
      mockReq = {
        body: {
          oldPassword: "oldPassword",
          newPassword: "newPassword"
        },
        auth: {
          userId: "mock-user-id"
        }
      } as Request;

      // Mocks
      jest.spyOn(AuthService.prototype, "changePassword").mockImplementationOnce(() => Promise.resolve());

      const mockSendResponse = jest.spyOn(SuccessWithNoData.prototype, "sendResponse");

      // Acts
      await authController.changePassword(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.changePassword).toHaveBeenCalledWith(mockReq.body, mockReq.auth.userId);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.PASSWORD_CHANGED
      });
    });
  });

  describe("Refresh token.", () => {
    it("Returns 400, when unable to create new access token.", async () => {
      mockReq = {
        body: {
          refreshToken: "mock-refresh-token"
        }
      } as Request;

      const mockError = new Error("Something went wrong, unable to create new access token.");

      // Mocks
      jest.spyOn(AuthService.prototype, "refreshToken").mockRejectedValueOnce(mockError);

      // Acts
      await authController.refreshToken(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.refreshToken).toHaveBeenCalledWith(mockReq.body.refreshToken);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_GENERATING_ACCESS_TOKEN, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when access token generated successfully.", async () => {
      mockReq = {
        body: {
          refreshToken: "mock-refresh-token"
        }
      } as Request;

      const mockResponse = {
        accessToken: "new-mock-access_token",
        refreshToken: mockReq.body.refreshToken
      };

      // Mocks
      jest.spyOn(AuthService.prototype, "refreshToken").mockResolvedValueOnce(mockResponse);

      const mockSendResponse = jest.spyOn(SuccessResponse.prototype, "sendResponse");

      // Acts
      await authController.refreshToken(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.refreshToken).toHaveBeenCalledWith(mockReq.body.refreshToken);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.ACCESS_TOKEN_FETCHED,
        data: mockResponse
      });
    });
  });

  describe("Search Friends.", () => {
    it("Returns 400, when unable to search friends.", async () => {
      mockReq = {
        auth: {
          userId: "mock-user-id"
        },
        query: {}
      } as Request;

      const mockError = new Error("Something went wrong, unable to search friends.");

      // Mocks
      jest.spyOn(AuthService.prototype, "searchFriends").mockRejectedValueOnce(mockError);

      // Acts
      await authController.searchFriends(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.searchFriends).toHaveBeenCalledWith(mockReq.query, mockReq.auth.userId);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_SEARCH_FRIENDS, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when access token generated successfully.", async () => {
      mockReq = {
        auth: {
          userId: "mock-user-id"
        },
        query: {}
      } as Request;

      const mockResponse = {
        users: [
          {
            ...mockUser,
            Profiles: {
              ...mockUser.Profiles,
              company: "mock-compony-name",
              address: "mock-address"
            }
          }
        ],
        totalCount: 1
      };

      // Mocks
      jest.spyOn(AuthService.prototype, "searchFriends").mockResolvedValueOnce(mockResponse);

      const mockSendResponse = jest.spyOn(SuccessResponseWithPagination.prototype, "sendResponse");

      // Acts
      await authController.searchFriends(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.searchFriends).toHaveBeenCalledWith(mockReq.query, mockReq.auth.userId);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.SEARCH_USER,
        data: mockResponse.users,
        total_count: mockResponse.totalCount
      });
    });
  });

  describe("Show user details.", () => {
    it("Returns 400, when unable to get user details.", async () => {
      mockReq = {
        auth: {
          userId: "mock-user-id"
        }
      } as Request;

      const mockError = new Error("Something went wrong, unable to get user details.");

      // Mocks
      jest.spyOn(AuthService.prototype, "show").mockRejectedValueOnce(mockError);

      // Acts
      await authController.show(mockReq, mockRes, mockNext);

      // Expectations
      expect(AuthService.prototype.show).toHaveBeenCalledWith(mockReq.auth.userId);

      expect(logger.error).toHaveBeenCalledWith(AUTH_ERROR_MESSAGE.ERROR_ON_SHOW_DETAILS, mockError);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });

    it("Returns 200, when user details fetched successfully.", async () => {
      mockReq = {
        auth: {
          userId: "mock-user-id"
        }
      } as Request;

      const mockResponse = {
        ...mockUser,
        Profiles: {
          ...mockUser.Profiles,
          company: "mock-compony-name",
          address: "mock-address"
        }
      };

      // Mocks
      jest.spyOn(AuthService.prototype, "show").mockResolvedValueOnce(mockResponse);

      const mockSendResponse = jest.spyOn(SuccessResponse.prototype, "sendResponse");

      // Acts
      await authController.show(mockReq, mockRes, mockNext);

      // Expectations
      expect(mockSendResponse).toHaveBeenCalled();
      expect(mockSendResponse.mock.calls[0][0]).toBe(mockRes);
      expect(AuthService.prototype.show).toHaveBeenCalledWith(mockReq.auth.userId);
      expect(mockSendResponse).toHaveBeenCalledWith(mockRes);

      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({
        success: true,
        message: AUTH_SUCCESS_MESSAGE.USER_DETAIL_FETCHED,
        data: mockResponse
      });
    });
  });
});
 */
