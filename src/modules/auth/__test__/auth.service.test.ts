/* 
import kafkaClient from "src/events";
import bcrypt from "bcrypt";
import { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import { generateDeterministicHash, OtpUtil } from "@shareModule/chat-app";
import { UserIdTopicCreator } from "src/events/admin-client/userIdTopicCreator.topic";
import { AuthRepository } from "../auth.repository";
import { InvitationCodeTrackerRepository } from "src/modules/invitationCodeTracker/invitationCodeTracker.repository";
import { BlockedUserRepository } from "src/modules/blocked-user/blockedUser.repository";
import { ResetOtpTrackerRepository } from "../../resetOtpTracker/resetOtpTracker.repository";
import { RefreshTokenRepository } from "src/modules/refreshToken/refreshToken.repository";
import * as jwtHelper from "src/helpers/jwt";
import * as sharedModule from "@shareModule/shared";
import { AuthService } from "../auth.service";
import { AUTH_ERROR_MESSAGE, AUTH_SUCCESS_MESSAGE } from "../auth.constant";
import { SESSION_ERROR_MESSAGE, SessionService } from "src/modules/session";
import envConfig from "src/config/app.config";

// Modules mocks
jest.mock("@shareModule/chat-app");
jest.mock("src/modules/invitationCodeTracker/invitationCodeTracker.repository");
jest.mock("../../resetOtpTracker/resetOtpTracker.repository");
jest.mock("../auth.repository");
jest.mock("bcrypt");
jest.mock("src/events", () => ({ createTopicIfNotExists: jest.fn() }));
jest.mock("src/events/admin-client/userIdTopicCreator.topic");
jest.mock("express-useragent");
jest.mock("src/helpers/jwt");
jest.mock("@shareModule/shared", () => {
  return {
    ...jest.requireActual("@shareModule/shared"),
    verifyToken: jest.fn().mockReturnValue("works!")
  };
});

let authService: AuthService;

let mockReq: Request;
describe("Authservice.", () => {
  beforeEach(() => {
    authService = new AuthService();

    mockReq = {} as Request;
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  const randomInvitedCode = "r@nd0mHA$h";
  const payload = {
    username: "garcia_101",
    email: "garcia101@yopmail.com",
    password: "P@ssw0rd#",
    fullname: "Naomi Garcia",
    phoneNumber: "1234567890",
    countryCode: "+977",
    invitationCode: "DRW45O"
  };

  describe("Signup User.", () => {
    const mockUser = {
      id: uuidv4(),
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.phoneNumber as string,
      isDeleted: false,
      password: "randomPassword",
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: {
        profilePic: "profile.png"
      }
    };

    it("Returns 401, when invitation code is invalid.", async () => {
      // Mocks
      (generateDeterministicHash as jest.Mock).mockReturnValueOnce(randomInvitedCode);

      jest.spyOn(InvitationCodeTrackerRepository.prototype, "findByInvitationCode").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.signup(payload)).rejects.toThrow(AUTH_ERROR_MESSAGE.INVITATION_CODE_NOT_EXISTS);
      expect(generateDeterministicHash).toHaveBeenCalledWith(payload.invitationCode);
      expect(InvitationCodeTrackerRepository.prototype.findByInvitationCode).toHaveBeenCalledWith(randomInvitedCode);
    });

    it("Return 409, when invitation code is already used.", async () => {
      // Mocks
      (generateDeterministicHash as jest.Mock).mockReturnValueOnce(randomInvitedCode);

      jest.spyOn(InvitationCodeTrackerRepository.prototype, "findByInvitationCode").mockResolvedValueOnce({
        id: uuidv4(),
        invitationCode: randomInvitedCode,
        isUsed: true
      });

      // Expectations
      await expect(authService.signup(payload)).rejects.toThrow(AUTH_ERROR_MESSAGE.INVITATION_CODE_ALREADY_USED);
      expect(generateDeterministicHash).toHaveBeenCalledWith(payload.invitationCode);
      expect(InvitationCodeTrackerRepository.prototype.findByInvitationCode).toHaveBeenCalledWith(randomInvitedCode);
    });

    it("Return 409, when username is already taken.", async () => {
      // Mocks
      (generateDeterministicHash as jest.Mock).mockReturnValueOnce(randomInvitedCode);

      jest.spyOn(InvitationCodeTrackerRepository.prototype, "findByInvitationCode").mockResolvedValueOnce({
        id: uuidv4(),
        invitationCode: randomInvitedCode,
        isUsed: false
      });

      const queryPayload = {
        username: payload.username,
        email: payload.email,
        phoneNumber: payload.phoneNumber as string,
        countryCode: payload.countryCode
      };

      jest.spyOn(authService, "validateSignupData").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.USER_NAME_EXIST));

      // Expectations
      await expect(authService.signup(payload)).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NAME_EXIST);
      expect(generateDeterministicHash).toHaveBeenCalledWith(payload.invitationCode);
      expect(InvitationCodeTrackerRepository.prototype.findByInvitationCode).toHaveBeenCalledWith(randomInvitedCode);
      expect(authService.validateSignupData).toHaveBeenCalledWith(queryPayload);
    });

    it("Return 409, when email is already taken.", async () => {
      // Mocks
      (generateDeterministicHash as jest.Mock).mockReturnValueOnce(randomInvitedCode);

      jest.spyOn(InvitationCodeTrackerRepository.prototype, "findByInvitationCode").mockResolvedValueOnce({
        id: uuidv4(),
        invitationCode: randomInvitedCode,
        isUsed: false
      });

      const queryPayload = {
        username: payload.username,
        email: payload.email,
        phoneNumber: payload.phoneNumber as string,
        countryCode: payload.countryCode
      };

      jest.spyOn(authService, "validateSignupData").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.EMAIL_EXIST));

      // Expectations
      await expect(authService.signup(payload)).rejects.toThrow(AUTH_ERROR_MESSAGE.EMAIL_EXIST);
      expect(generateDeterministicHash).toHaveBeenCalledWith(payload.invitationCode);
      expect(InvitationCodeTrackerRepository.prototype.findByInvitationCode).toHaveBeenCalledWith(randomInvitedCode);
      expect(authService.validateSignupData).toHaveBeenCalledWith(queryPayload);
    });

    it("Return 409, when phone number is already taken.", async () => {
      // Mocks
      (generateDeterministicHash as jest.Mock).mockReturnValueOnce(randomInvitedCode);

      jest.spyOn(InvitationCodeTrackerRepository.prototype, "findByInvitationCode").mockResolvedValueOnce({
        id: uuidv4(),
        invitationCode: randomInvitedCode,
        isUsed: false
      });

      const queryPayload = {
        username: payload.username,
        email: payload.email,
        phoneNumber: payload.phoneNumber as string,
        countryCode: payload.countryCode
      };

      jest.spyOn(authService, "validateSignupData").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.PHONE_NUMBER_EXIST));

      // Expectations
      await expect(authService.signup(payload)).rejects.toThrow(AUTH_ERROR_MESSAGE.PHONE_NUMBER_EXIST);
      expect(generateDeterministicHash).toHaveBeenCalledWith(payload.invitationCode);
      expect(InvitationCodeTrackerRepository.prototype.findByInvitationCode).toHaveBeenCalledWith(randomInvitedCode);
      expect(authService.validateSignupData).toHaveBeenCalledWith(queryPayload);
    });

    it("Return 201, Calls kafka events after user created successfully.", async () => {
      const queryPayload = {
        username: payload.username,
        email: payload.email,
        phoneNumber: payload.phoneNumber as string,
        countryCode: payload.countryCode
      };

      // mocks
      (generateDeterministicHash as jest.Mock).mockReturnValueOnce(randomInvitedCode);

      jest.spyOn(InvitationCodeTrackerRepository.prototype, "findByInvitationCode").mockResolvedValueOnce({
        id: uuidv4(),
        invitationCode: randomInvitedCode,
        isUsed: false
      });

      jest.spyOn(authService, "validateSignupData");

      jest.spyOn(bcrypt, "hash").mockImplementationOnce(() => Promise.resolve("hashedPassword"));

      jest.spyOn(AuthRepository.prototype, "createProduceUserAndRevokedInvitationCode").mockResolvedValueOnce(mockUser);

      const user = await authService.signup(payload);

      // Kafka event mocking
      const topicCreator = new UserIdTopicCreator(kafkaClient, user.id);
      await topicCreator.createTopicIfNotExists(5);

      // Expectations
      expect(user).toBeDefined();
      expect(user).toEqual(mockUser);
      expect(generateDeterministicHash).toHaveBeenCalledWith("DRW45O");
      expect(InvitationCodeTrackerRepository.prototype.findByInvitationCode).toHaveBeenCalledWith(randomInvitedCode);
      expect(authService.validateSignupData).toHaveBeenCalledWith(queryPayload);
      expect(bcrypt.hash).toHaveBeenCalledWith("P@ssw0rd#", 10);
      expect(AuthRepository.prototype.createProduceUserAndRevokedInvitationCode).toHaveBeenCalledTimes(1);
      expect(AuthRepository.prototype.createProduceUserAndRevokedInvitationCode).toHaveBeenCalledWith({
        ...payload,
        password: "hashedPassword",
        invitationCode: randomInvitedCode
      });
      expect(UserIdTopicCreator).toHaveBeenCalledWith(kafkaClient, user.id);
      expect(topicCreator.createTopicIfNotExists).toHaveBeenCalledWith(5);
    });
  });

  describe("Validate Signup Data.", () => {
    let query = {};

    const mockUser = {
      id: uuidv4(),
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      password: "randomPassword",
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: {
        profilePic: "profile.png"
      }
    };

    it("Returns 409, when user name is already exits", async () => {
      query = {
        username: { equals: payload.username, mode: "insensitive" }
      };

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(mockUser);

      await expect(authService.validateSignupData({ username: payload.username })).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NAME_EXIST);
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith(query);
    });

    it("Returns 409, when email is already exits", async () => {
      query = {
        email: { equals: payload.email, mode: "insensitive" }
      };

      jest
        .spyOn(AuthRepository.prototype, "findUserByAttributes")
        .mockResolvedValueOnce(null) // email
        .mockResolvedValueOnce(mockUser); //username

      await expect(
        authService.validateSignupData({
          username: payload.username,
          email: payload.email
        })
      ).rejects.toThrow(AUTH_ERROR_MESSAGE.EMAIL_EXIST);
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith(query);
    });

    it("Returns 409, when phone number is already exits", async () => {
      jest
        .spyOn(AuthRepository.prototype, "findUserByAttributes")
        .mockResolvedValueOnce(null) // email
        .mockResolvedValueOnce(null) // username
        .mockResolvedValueOnce(mockUser); //phoneNumber

      await expect(
        authService.validateSignupData({
          username: payload.username,
          email: payload.email,
          phoneNumber: payload.phoneNumber as string,
          countryCode: payload.countryCode
        })
      ).rejects.toThrow(AUTH_ERROR_MESSAGE.PHONE_NUMBER_EXIST);
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({
        AND: [{ countryCode: payload.countryCode }, { phoneNumber: payload.phoneNumber }]
      });

      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledTimes(3);
    });
  });

  describe("Login User.", () => {
    const loginPayload = {
      username: payload.username,
      password: payload.password
    };

    const password = "randomPassword";
    const sessionId = "randomSessionId";
    const mockUser = {
      id: uuidv4(),
      fullname: "randomFullName",
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: {
        profilePic: "profile.png"
      }
    };

    it("Return 404, when username is invalid.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ username: loginPayload.username });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(null);

      // Expectations
      await expect(
        authService.login(loginPayload, sessionId, {
          ...mockReq.useragent,
          ipAddress: "yourIpAddress"
        })
      ).rejects.toThrow(AUTH_ERROR_MESSAGE.INVALID_CREDENTIAL);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({
        username: loginPayload.username
      });
    });

    it("Return 404, when password is invalid.", async () => {
      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ username: loginPayload.username });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({ ...mockUser, password });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(false));

      // Expectations
      await expect(
        authService.login(loginPayload, sessionId, {
          ...mockReq.useragent,
          ipAddress: "yourIpAddress"
        })
      ).rejects.toThrow(AUTH_ERROR_MESSAGE.INVALID_CREDENTIAL);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(loginPayload.password, password);
    });

    it("Return 400, when unable to create session.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ username: loginPayload.username });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({ ...mockUser, password });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(true));

      jest.spyOn(authService, "loginPayloadWithSession").mockRejectedValueOnce(new Error(SESSION_ERROR_MESSAGE.SESSION_NOT_FOUND));

      // Expectations
      await expect(
        authService.login(loginPayload, sessionId, {
          ...mockReq.useragent,
          ipAddress: "yourIpAddress"
        })
      ).rejects.toThrow(SESSION_ERROR_MESSAGE.SESSION_NOT_FOUND);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(loginPayload.password, password);
      expect(authService.loginPayloadWithSession).toHaveBeenCalledWith(mockUser, sessionId, {
        ...mockReq.useragent,
        ipAddress: "yourIpAddress"
      });
    });

    it("Return 200 and create session, when user login successfully.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ username: loginPayload.username });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({ ...mockUser, password });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(true));

      jest.spyOn(authService, "loginPayloadWithSession").mockResolvedValueOnce({
        accessToken: "randomAccessToken",
        refreshToken: "randomRefreshToken",
        user: mockUser,
        sessionId: "randomSessionId"
      });

      // Expectations
      const user = await authService.login(loginPayload, sessionId, {
        ...mockReq.useragent,
        ipAddress: "yourIpAddress"
      });
      expect(user).toBeDefined();
      expect(user).toEqual({
        accessToken: "randomAccessToken",
        refreshToken: "randomRefreshToken",
        user: mockUser,
        sessionId: "randomSessionId"
      });
      expect(authService.constructQuery).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({
        username: loginPayload.username
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(loginPayload.password, password);
      expect(authService.loginPayloadWithSession).toHaveBeenCalledWith(mockUser, sessionId, {
        ...mockReq.useragent,
        ipAddress: "yourIpAddress"
      });
    });
  });

  describe("Check user already registered.", () => {
    const mockUser = {
      id: uuidv4(),
      fullname: "randomFullName",
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: {
        profilePic: "profile.png"
      }
    };

    it("Return 409, when username is already used by user.", async () => {
      //mocks

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({ ...mockUser, password: "randomPassword" });

      const response = await authService.checkRegisteredUser({
        username: payload.username
      });

      // Expectations
      expect(response).toBeDefined();
      expect(response).toEqual({
        isRegistered: true,
        message: AUTH_ERROR_MESSAGE.USERNAME_ALREADY_TAKEN
      });
    });

    it("Return 409, when email is already used by user.", async () => {
      //mocks

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({ ...mockUser, password: "randomPassword" });

      const response = await authService.checkRegisteredUser({
        email: payload.email
      });

      // Expectations
      expect(response).toBeDefined();
      expect(response).toEqual({
        isRegistered: true,
        message: AUTH_ERROR_MESSAGE.EMAIL_ALREADY_TAKEN
      });
    });

    it("Return 409, when phone number is already used by user.", async () => {
      //mocks

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({ ...mockUser, password: "randomPassword" });

      const response = await authService.checkRegisteredUser({
        countryCode: payload.countryCode,
        phoneNumber: payload.phoneNumber as string
      });

      // Expectations
      expect(response).toBeDefined();
      expect(response).toEqual({
        isRegistered: true,
        message: AUTH_ERROR_MESSAGE.PHONE_NUMBER_ALREADY_TAKEN
      });
    });

    it("Return 200, when username, email and phone number is not already used by user.", async () => {
      //mocks

      jest
        .spyOn(AuthRepository.prototype, "findUserByAttributes")
        .mockResolvedValueOnce(null) // username
        .mockResolvedValueOnce(null) // email
        .mockResolvedValueOnce(null); // phone number

      const response = await authService.checkRegisteredUser({
        username: payload.username,
        email: payload.email,
        phoneNumber: payload.phoneNumber as string
      });

      // Expectations
      expect(response).toBeDefined();
      expect(response).toEqual({
        isRegistered: false,
        message: AUTH_SUCCESS_MESSAGE.VALIDATE_SUCCESSFULLY
      });
    });
  });

  describe("Logout User.", () => {
    const sessionId = "randomSessionId";

    const userId = uuidv4();

    it("returns 200, when user logout for one device.", async () => {
      // Mocks
      jest.spyOn(SessionService.prototype, "delete").mockResolvedValueOnce({ sessionId, userId });

      const response = await authService.logout(sessionId);

      // Expectations
      expect(response).toBeDefined();
      expect(response).toEqual({
        sessionId,
        userId
      });
      expect(SessionService.prototype.delete).toHaveBeenCalledWith(sessionId);
    });

    it("returns 200, when user logout for multi-devices.", async () => {
      // Mocks
      jest.spyOn(SessionService.prototype, "deleteAll").mockImplementationOnce(() => Promise.resolve());

      await authService.logoutAll(userId);

      // Expectations
      expect(SessionService.prototype.deleteAll).toHaveBeenCalledWith(userId);
    });
  });

  describe("Created User login payload with session.", () => {
    const sessionId = "randomSessionId";

    const mockUser = {
      id: uuidv4(),
      fullname: "randomFullName",
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: {
        profilePic: "profile.png"
      }
    };

    it("Returns 404, when user session record not found.", async () => {
      const metaDataInfo = {
        ...mockReq.useragent,
        ipAddress: "yourIpAddress"
      };

      const mockTokens = {
        accessToken: "accessToken",
        refreshToken: "refreshToken"
      };

      // Mocks
      jest.spyOn(jwtHelper, "generateTokens").mockReturnValueOnce(mockTokens);
      jest.spyOn(bcrypt, "hash").mockImplementationOnce(() => Promise.resolve("hashedRefreshToken"));

      // with instance
      const sessionServiceInstance = new SessionService();

      jest.spyOn(sessionServiceInstance, "getRecord").mockResolvedValueOnce(null);

      const record = await sessionServiceInstance.getRecord(sessionId, mockUser.id);

      // Expectations
      await expect(authService.loginPayloadWithSession(mockUser, sessionId, metaDataInfo)).rejects.toThrow(SESSION_ERROR_MESSAGE.SESSION_NOT_FOUND);
      expect(jwtHelper.generateTokens).toHaveBeenCalledTimes(1);
      expect(bcrypt.hash).toHaveBeenCalledWith(mockTokens.refreshToken, 10);
      expect(record).toBeNull();
      expect(sessionServiceInstance.getRecord).toHaveBeenCalledWith(sessionId, mockUser.id);
    });

    it("Returns 200, when successfully user session is created.", async () => {
      const metaDataInfo = {
        ...mockReq.useragent,
        ipAddress: "yourIpAddress"
      };

      const mockTokens = {
        accessToken: "accessToken",
        refreshToken: "refreshToken"
      };

      const mockUserSession = {
        sessionData: {
          userId: mockUser.id,
          sessionId
        },
        metaData: {
          ...mockReq.useragent,
          ipAddress: "yourIpAddress"
        }
      };

      // Mocks
      jest.spyOn(jwtHelper, "generateTokens").mockReturnValueOnce(mockTokens);

      jest.spyOn(bcrypt, "hash").mockImplementationOnce(() => Promise.resolve("hashedRefreshToken"));

      jest.spyOn(SessionService.prototype, "getSessionAndMetaData").mockReturnValueOnce(mockUserSession);

      jest.spyOn(SessionService.prototype, "createRecordAndRefreshToken").mockResolvedValueOnce({ userId: mockUser.id, sessionId });

      const response = await authService.loginPayloadWithSession(
        mockUser,
        null, // because to bypass the "sessionService.getRecord", which doesn't mocking now

        metaDataInfo
      );

      // Expectations
      expect(response).toBeDefined();
      expect(response).toEqual({
        ...mockTokens,
        user: mockUser,
        sessionId
      });
      expect(jwtHelper.generateTokens).toHaveBeenCalledTimes(1);
      expect(bcrypt.hash).toHaveBeenCalledWith(mockTokens.refreshToken, 10);
      expect(SessionService.prototype.getSessionAndMetaData).toHaveBeenCalledWith(mockUserSession.sessionData.userId, mockUserSession.metaData);
      expect(SessionService.prototype.createRecordAndRefreshToken).toHaveBeenCalledTimes(1);
    });
  });

  describe("Construct query.", () => {
    it.todo("Create where auth query");
  });

  describe("Search Friends.", () => {
    const userId = uuidv4();

    const mockSearchedResponse = [
      {
        id: uuidv4(),
        fullname: payload.fullname,
        username: payload.username,
        email: payload.email,
        phoneNumber: payload.phoneNumber as string,
        countryCode: payload.countryCode,
        isDeleted: false,
        resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
        Profiles: null
      }
    ];

    it("returns 200, when the user search his/her friends", async () => {
      const mockQuery = {
        pageSize: "5",
        page: "1",
        username: "Rolando"
      };

      // Mock
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ username: mockQuery.username });
      jest.spyOn(AuthRepository.prototype, "searchFriends").mockResolvedValueOnce({
        users: mockSearchedResponse,
        totalCount: mockSearchedResponse.length
      });

      const query = {
        searchQuery: { username: mockQuery.username, id: { not: userId } },
        pageSize: +mockQuery.pageSize,
        page: (+mockQuery.page - 1) * +mockQuery.pageSize
      };

      jest.spyOn(BlockedUserRepository.prototype, "blockedList").mockResolvedValueOnce([]); // no blocked user

      // Expectations
      const response = await authService.searchFriends(mockQuery, userId);
      expect(response).toBeDefined();
      expect(response).toEqual({
        users: mockSearchedResponse,
        totalCount: mockSearchedResponse.length
      });
      expect(authService.constructQuery).toHaveBeenCalledWith(mockQuery);
      expect(AuthRepository.prototype.searchFriends).toHaveBeenCalledWith(query.searchQuery, query.pageSize, query.page);
    });
  });

  describe("Show user details.", () => {
    const userId = uuidv4();

    const mockUser = {
      id: userId,
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: null
    };

    it("returns 404, when user details not found.", async () => {
      // Mocks
      jest.spyOn(authService, "show").mockResolvedValueOnce(null);

      // Expectations
      const response = await authService.show(userId);
      expect(response).toBeNull();
      expect(authService.show).toHaveBeenCalledWith(userId);
    });

    it("returns 200, when user details found.", async () => {
      // Mocks
      jest.spyOn(authService, "show").mockResolvedValueOnce(mockUser);

      // Expectations
      const response = await authService.show(userId);
      expect(response).toBeDefined();
      expect(response).toEqual(mockUser);
      expect(authService.show).toHaveBeenCalledWith(userId);
    });
  });

  describe("Send Email.", () => {
    const mockUser = {
      id: uuidv4(),
      fullname: "randomFullName",
      username: payload.username,
      email: payload.email,
      password: "randomPassword",
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1),
      Profiles: {
        profilePic: "profile.png"
      }
    };

    it("404, when user record not found", async () => {
      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: mockUser.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.sendEmail(mockUser.email)).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NOT_EXIST);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: mockUser.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: mockUser.email });
    });

    it("200, creates otp and send mail successfully", async () => {
      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: mockUser.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(mockUser);

      jest.spyOn(OtpUtil.prototype, "generateOtp").mockReturnValueOnce("randomOPT");

      jest.spyOn(ResetOtpTrackerRepository.prototype, "createOrUpdateAndResetExpirationDate");

      // Expectations
      const otp = OtpUtil.prototype.generateOtp(mockUser.username);

      await authService.sendEmail(mockUser.email);
      expect(otp).toEqual("randomOPT");
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: mockUser.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({
        email: mockUser.email
      });
      expect(OtpUtil.prototype.generateOtp).toHaveBeenCalledWith(mockUser.username);
      expect(ResetOtpTrackerRepository.prototype.createOrUpdateAndResetExpirationDate).toHaveBeenCalledTimes(1);
    });
  });

  describe("Reset Password.", () => {
    const mockUser = {
      id: uuidv4(),
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1)
    };

    const mockPayload = {
      email: mockUser.email,
      newPassword: "newPassword"
    };

    it("Returns 404, when user record not found.", async () => {
      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.resetPassword(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NOT_EXIST);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
    });

    it("Returns 401, when reset password OTP is not verified.", async () => {
      mockUser.resetPasswordExpiration = new Date(new Date().getTime() - 1000 * 60 * 60 * 1);

      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashedPassword",
        Profiles: {
          profilePic: "profile.png"
        }
      });

      // Expectations
      await expect(authService.resetPassword(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.RESET_PASSWORD_OTP_NOT_VERIFIED);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
    });

    it("Returns 400, when new password is same as old one.", async () => {
      const userHashPassword = "hashedPassword";

      mockUser.resetPasswordExpiration = new Date(new Date().getTime() + 1000 * 60 * 60 * 1);

      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: userHashPassword,
        Profiles: {
          profilePic: "profile.png"
        }
      });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(true));

      // Expectations
      await expect(authService.resetPassword(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.SAME_PASSWORD);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.newPassword, userHashPassword);
    });

    it("Returns 200, password is reset successfully verified", async () => {
      const userHashPassword = "hashedPassword";
      const userNewHashPassword = "newHashPassword";

      mockUser.resetPasswordExpiration = new Date(new Date().getTime() + 1000 * 60 * 60 * 1);

      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: userHashPassword,
        Profiles: {
          profilePic: "profile.png"
        }
      });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(false));

      jest.spyOn(bcrypt, "hash").mockImplementationOnce(() => Promise.resolve(userNewHashPassword));

      jest.spyOn(AuthRepository.prototype, "updateAndProducePasswordAndRevokedToken");

      jest.spyOn(ResetOtpTrackerRepository.prototype, "removeResetOtp");

      await authService.resetPassword(mockPayload);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.newPassword, userHashPassword);
      expect(bcrypt.hash).toHaveBeenCalledWith(mockPayload.newPassword, 10);
      expect(AuthRepository.prototype.updateAndProducePasswordAndRevokedToken).toHaveBeenCalledWith(userNewHashPassword, mockUser.id);
      expect(ResetOtpTrackerRepository.prototype.removeResetOtp).toHaveBeenCalledWith(mockUser.id);
    });
  });

  describe("Verify and reset password OTP.", () => {
    const mockUser = {
      id: uuidv4(),
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1)
    };

    const mockPayload = {
      email: mockUser.email,
      otp: "randomOTP"
    };

    const mockOTPTrack = {
      id: uuidv4(),
      otp: "RANDOMOTP",
      userId: mockUser.id,
      expirationDate: new Date(),
      failedAttempt: 2,
      blockedFeatureTime: new Date()
    };

    it("Returns 404, when user record not found.", async () => {
      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.verifyResetPasswordOtp(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NOT_EXIST);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
    });

    it("Returns 404, when otp record not found.", async () => {
      // Mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashPassword",
        Profiles: { profilePic: "profile.png" }
      });

      jest.spyOn(authService, "findResetOtpTracker").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.OPT_RECORD_NOT_FOUND));

      // Expectations
      await expect(authService.verifyResetPasswordOtp(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.OPT_RECORD_NOT_FOUND);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(authService.findResetOtpTracker).toHaveBeenCalledWith(mockUser.id);
    });

    it("Returns 401, when OPT is attempt more the 5.", async () => {
      // Mocks
      mockOTPTrack.failedAttempt = 6;

      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashPassword",
        Profiles: { profilePic: "profile.png" }
      });

      jest.spyOn(authService, "findResetOtpTracker").mockResolvedValueOnce(mockOTPTrack);

      jest.spyOn(authService, "checkFailedAttempts").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.OTP_FAILED_ATTEMPT));

      // Expectations
      await expect(authService.verifyResetPasswordOtp(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.OTP_FAILED_ATTEMPT);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(authService.findResetOtpTracker).toHaveBeenCalledWith(mockUser.id);
      expect(authService.checkFailedAttempts).toHaveBeenCalledWith(mockOTPTrack);
    });

    it("Returns 400, when OPT does not matched.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashPassword",
        Profiles: { profilePic: "profile.png" }
      });

      jest.spyOn(authService, "findResetOtpTracker").mockResolvedValueOnce(mockOTPTrack);

      jest.spyOn(authService, "checkFailedAttempts").mockResolvedValueOnce();

      jest.spyOn(authService, "checkOtpMatch").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.OTP_NOT_MATCHED));

      // Expectations
      await expect(authService.verifyResetPasswordOtp(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.OTP_NOT_MATCHED);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(authService.findResetOtpTracker).toHaveBeenCalledWith(mockUser.id);
      expect(authService.checkFailedAttempts).toHaveBeenCalledWith(mockOTPTrack);
      expect(authService.checkOtpMatch).toHaveBeenCalledWith(mockPayload.otp, mockOTPTrack, mockUser.id);
    });

    it("Returns 401, when OPT is expired.", async () => {
      // AUTH_ERROR_MESSAGE.OTP_EXPIRED

      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });
      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashPassword",
        Profiles: { profilePic: "profile.png" }
      });
      jest.spyOn(authService, "findResetOtpTracker").mockResolvedValueOnce(mockOTPTrack);

      jest.spyOn(authService, "checkFailedAttempts").mockResolvedValueOnce();
      jest.spyOn(authService, "checkOtpMatch").mockResolvedValueOnce();
      jest.spyOn(authService, "checkOtpExpiration").mockRejectedValueOnce(new Error(AUTH_ERROR_MESSAGE.OTP_EXPIRED));

      // Expectations
      await expect(authService.verifyResetPasswordOtp(mockPayload)).rejects.toThrow(AUTH_ERROR_MESSAGE.OTP_EXPIRED);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(authService.findResetOtpTracker).toHaveBeenCalledWith(mockUser.id);
      expect(authService.checkFailedAttempts).toHaveBeenCalledWith(mockOTPTrack);
      expect(authService.checkOtpMatch).toHaveBeenCalledWith(mockPayload.otp, mockOTPTrack, mockUser.id);
      expect(authService.checkOtpExpiration).toHaveBeenCalledWith(mockOTPTrack, mockUser.id);
    });

    it("Returns 200, when OTP and password successfully reset.", async () => {
      const currentDate = new Date();

      currentDate.setMinutes(currentDate.getMinutes() + 5);

      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ email: payload.email });
      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashPassword",
        Profiles: { profilePic: "profile.png" }
      });
      jest.spyOn(authService, "findResetOtpTracker").mockResolvedValueOnce(mockOTPTrack);

      jest.spyOn(authService, "checkFailedAttempts").mockResolvedValueOnce();
      jest.spyOn(authService, "checkOtpMatch").mockResolvedValueOnce();
      jest.spyOn(authService, "checkOtpExpiration").mockResolvedValueOnce();
      jest.spyOn(AuthRepository.prototype, "updateResetPasswordExpiration").mockResolvedValueOnce();

      // Expectations
      await authService.verifyResetPasswordOtp(mockPayload);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        email: payload.email
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ email: payload.email });
      expect(authService.findResetOtpTracker).toHaveBeenCalledWith(mockUser.id);
      expect(authService.checkFailedAttempts).toHaveBeenCalledWith(mockOTPTrack);
      expect(authService.checkOtpMatch).toHaveBeenCalledWith(mockPayload.otp, mockOTPTrack, mockUser.id);
      expect(authService.checkOtpExpiration).toHaveBeenCalledWith(mockOTPTrack, mockUser.id);
      expect(AuthRepository.prototype.updateResetPasswordExpiration).toHaveBeenCalledWith(mockUser.id, currentDate);
    });
  });

  describe("Find and Reset Otp Tracker.", () => {
    const mockUser = {
      id: uuidv4(),
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1)
    };

    const mockOTPTrack = {
      id: uuidv4(),
      otp: "RANDOMOTP",
      userId: mockUser.id,
      expirationDate: new Date(),
      failedAttempt: 2,
      blockedFeatureTime: new Date()
    };

    it("Returns 404, when otp tracker record not found,", async () => {
      // Mocks
      jest.spyOn(ResetOtpTrackerRepository.prototype, "findByUserId").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.findResetOtpTracker(mockUser.id)).rejects.toThrow(AUTH_ERROR_MESSAGE.OPT_RECORD_NOT_FOUND);
      expect(ResetOtpTrackerRepository.prototype.findByUserId).toHaveBeenCalledWith(mockUser.id);
    });

    it("Returns 200, when otp tracker fetched successfully,", async () => {
      // Mocks
      jest.spyOn(ResetOtpTrackerRepository.prototype, "findByUserId").mockResolvedValueOnce(mockOTPTrack);

      // Expectations
      const response = await authService.findResetOtpTracker(mockUser.id);
      expect(response).toBeDefined();
      expect(response).toEqual(mockOTPTrack);
      expect(ResetOtpTrackerRepository.prototype.findByUserId).toHaveBeenCalledWith(mockUser.id);
      expect(ResetOtpTrackerRepository.prototype.findByUserId).toHaveBeenCalledWith(mockUser.id);
    });
  });

  describe("Check OTP failed attempts.", () => {
    const mockPayload = {
      id: uuidv4(),
      otp: "RANDOMOTP",
      userId: uuidv4(),
      expirationDate: new Date(),
      failedAttempt: 9,
      blockedFeatureTime: new Date(AUTH_ERROR_MESSAGE.OTP_FAILED_ATTEMPT)
    };

    it("Returns 401, when OTP is attempt more than 5.", async () => {
      await expect(authService.checkFailedAttempts(mockPayload)).rejects.toThrow();
    });
  });

  describe("Check OTP expiration.", () => {
    const userId = uuidv4();

    const resetOtpTracker = {
      id: uuidv4(),
      otp: "RANDOMOTP",
      userId: userId,
      expirationDate: new Date(),
      failedAttempt: 2,
      blockedFeatureTime: new Date()
    };

    it("Returns 401, when OTP is expired.", async () => {
      const currentDate = new Date();

      currentDate.setMinutes(currentDate.getMinutes() - 5);

      resetOtpTracker.expirationDate = currentDate;

      jest.spyOn(authService, "blockedOtpFeature").mockResolvedValueOnce();

      jest.spyOn(AuthRepository.prototype, "updateResetPasswordExpiration").mockResolvedValueOnce();

      await expect(authService.checkOtpExpiration(resetOtpTracker, userId)).rejects.toThrow(AUTH_ERROR_MESSAGE.OTP_EXPIRED);
    });
  });

  describe("Check OTP Matched.", () => {
    const userId = uuidv4();

    const resetOtpTracker = {
      id: uuidv4(),
      otp: "RANDOMOTP",
      userId,
      expirationDate: new Date(),
      failedAttempt: 2,
      blockedFeatureTime: new Date()
    };

    it("Returns 400, when wrong OTP tries", async () => {
      const OTP = "randomOPT";

      const updatedOTPTracker = {
        ...resetOtpTracker,
        failedAttempt: resetOtpTracker.failedAttempt + 1
      };

      // mocks
      jest.spyOn(ResetOtpTrackerRepository.prototype, "updateResetOtpCount").mockResolvedValueOnce(updatedOTPTracker);

      jest.spyOn(authService, "blockedOtpFeature").mockResolvedValueOnce();

      // Exceptions

      await expect(authService.checkOtpMatch(OTP, resetOtpTracker, userId)).rejects.toThrow(AUTH_ERROR_MESSAGE.OTP_NOT_MATCHED);
      expect(ResetOtpTrackerRepository.prototype.updateResetOtpCount).toHaveBeenCalledWith(userId, updatedOTPTracker.failedAttempt);
      expect(authService.blockedOtpFeature).toHaveBeenCalledWith(updatedOTPTracker, userId);
    });
  });

  describe("Blocked OTP feature.", () => {
    const userId = uuidv4();

    const resetOtpTracker = {
      id: uuidv4(),
      otp: "RANDOMOTP",
      userId,
      expirationDate: new Date(),
      failedAttempt: 5,
      blockedFeatureTime: new Date()
    };

    it("returns 200, when the OTP feature is blocked.", async () => {
      const blockedFeatureTime = new Date();

      blockedFeatureTime.setMinutes(blockedFeatureTime.getMinutes() + 15);
      jest.spyOn(ResetOtpTrackerRepository.prototype, "blockedOtpGeneration");

      await authService.blockedOtpFeature(resetOtpTracker, userId);
      expect(ResetOtpTrackerRepository.prototype.blockedOtpGeneration).toHaveBeenCalledWith(userId, blockedFeatureTime);
    });
  });

  describe("Change Password.", () => {
    const mockPayload = {
      oldPassword: payload.password,
      newPassword: "NewPassword"
    };

    const mockUser = {
      id: uuidv4(),
      fullname: payload.fullname,
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1)
    };

    it("Returns 404, when user record not found.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ id: mockUser.id });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.changePassword(mockPayload, mockUser.id)).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NOT_EXIST);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        userId: mockUser.id
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ id: mockUser.id });
    });

    it("Returns 400, when old password is not valid.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ id: mockUser.id });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "HashedPassword",
        Profiles: {
          profilePic: "profile.png"
        }
      });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(false));

      // Expectations
      await expect(authService.changePassword(mockPayload, mockUser.id)).rejects.toThrow(AUTH_ERROR_MESSAGE.OLD_PASSWORD);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        userId: mockUser.id
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ id: mockUser.id });
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.oldPassword, "HashedPassword");
    });

    it("Returns 400, when old password and new password are same.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ id: mockUser.id });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "HashedPassword",
        Profiles: {
          profilePic: "profile.png"
        }
      });

      jest
        .spyOn(bcrypt, "compare")
        .mockImplementationOnce(() => Promise.resolve(true))
        .mockImplementationOnce(() => Promise.resolve(true));

      // Expectations
      await expect(authService.changePassword(mockPayload, mockUser.id)).rejects.toThrow(AUTH_ERROR_MESSAGE.SAME_PASSWORD);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        userId: mockUser.id
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ id: mockUser.id });
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.oldPassword, "HashedPassword");
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.newPassword, "HashedPassword");
    });

    it("Returns 200, when password changed successfully.", async () => {
      // mocks
      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ id: mockUser.id });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "HashedPassword",
        Profiles: {
          profilePic: "profile.png"
        }
      });

      jest
        .spyOn(bcrypt, "compare")
        .mockImplementationOnce(() => Promise.resolve(true))
        .mockImplementationOnce(() => Promise.resolve(false));

      jest.spyOn(bcrypt, "hash").mockImplementationOnce(() => Promise.resolve("newHashPassword"));

      jest.spyOn(AuthRepository.prototype, "updateAndProducePasswordAndRevokedToken").mockResolvedValueOnce();

      jest.spyOn(AuthRepository.prototype, "removeResetOtp").mockResolvedValueOnce({
        count: 1
      });

      await authService.changePassword(mockPayload, mockUser.id);

      // Expectations
      expect(authService.constructQuery).toHaveBeenCalledWith({
        userId: mockUser.id
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ id: mockUser.id });
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.oldPassword, "HashedPassword");
      expect(bcrypt.compare).toHaveBeenCalledWith(mockPayload.newPassword, "HashedPassword");
      expect(bcrypt.hash).toHaveBeenCalledWith(mockPayload.newPassword, 10);
      expect(AuthRepository.prototype.updateAndProducePasswordAndRevokedToken).toHaveBeenCalledWith("newHashPassword", mockUser.id);
    });
  });

  describe("Validate OTP Token.", () => {
    const OTP = "randomOTP";
    const username = payload.username;

    it("Returns 401, when users OTP is not validate.", async () => {
      // mocks
      jest.spyOn(OtpUtil.prototype, "verifyOtpToken").mockReturnValue(false);

      // Expectations
      expect(authService.validateOtpToken.bind(authService, OTP, username)).toThrow(new sharedModule.NotAuthorizedError(AUTH_ERROR_MESSAGE.OTP_EXPIRED));
      expect(OtpUtil.prototype.verifyOtpToken).toHaveBeenCalledWith(OTP, username);
    });

    it("Returns 200, when user OTP is validate", async () => {
      // mocks
      jest.spyOn(OtpUtil.prototype, "verifyOtpToken").mockReturnValue(true);

      // Expectations
      expect(() => authService.validateOtpToken(OTP, username)).not.toThrow();
      expect(OtpUtil.prototype.verifyOtpToken).toHaveBeenCalledWith(OTP, username);
    });
  });

  describe("Refresh Token.", () => {
    const refreshToken = "randomRefreshToken";

    const refreshSecret = envConfig.jwtConfig.REFRESH_TOKEN_SECRET;

    const jti = "JWT_ID";

    const mockUser = {
      id: uuidv4(),
      fullname: "randomFullName",
      username: payload.username,
      email: payload.email,
      phoneNumber: payload.phoneNumber as string,
      countryCode: payload.countryCode,
      isDeleted: false,
      resetPasswordExpiration: new Date(new Date().getTime() + 1000 * 60 * 60 * 1)
    };

    const mockRefreshToken = {
      id: uuidv4(),
      hashedToken: "hashToken",
      userId: mockUser.id,
      sessionId: "sessionId",
      createdAt: new Date(),
      updatedAt: new Date()
    };

    it("Returns 401, when refresh token JTI is not found.", async () => {
      // Mocks
      jest.spyOn(sharedModule, "verifyToken").mockReturnValue({});

      // Expectations
      await expect(authService.refreshToken(refreshToken)).rejects.toThrow(AUTH_ERROR_MESSAGE.REFRESH_TOKEN_ID_NOT_FOUND);
      expect(sharedModule.verifyToken).toHaveBeenCalledWith(refreshToken, refreshSecret);
    });

    it("Returns 401, when refresh token record not found.", async () => {
      // Mocks
      jest.spyOn(sharedModule, "verifyToken").mockReturnValue({ ...mockRefreshToken, jti });

      jest.spyOn(RefreshTokenRepository.prototype, "findRefreshTokenById").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.refreshToken(refreshToken)).rejects.toThrow(AUTH_ERROR_MESSAGE.REFRESH_TOKEN_REVOKED);
      expect(sharedModule.verifyToken).toHaveBeenCalledWith(refreshToken, refreshSecret);
      expect(RefreshTokenRepository.prototype.findRefreshTokenById).toHaveBeenCalledWith(jti);
    });

    it("Returns 401, when refresh token already revoked.", async () => {
      // Mocks
      jest.spyOn(sharedModule, "verifyToken").mockReturnValue({ ...mockRefreshToken, jti });

      jest.spyOn(RefreshTokenRepository.prototype, "findRefreshTokenById").mockResolvedValueOnce({ ...mockRefreshToken, revoked: true });

      // Expectations
      await expect(authService.refreshToken(refreshToken)).rejects.toThrow(AUTH_ERROR_MESSAGE.REFRESH_TOKEN_REVOKED);
      expect(sharedModule.verifyToken).toHaveBeenCalledWith(refreshToken, refreshSecret);
      expect(RefreshTokenRepository.prototype.findRefreshTokenById).toHaveBeenCalledWith(jti);
    });

    it("Return 401, when refresh token not matched", async () => {
      // Mocks
      jest.spyOn(sharedModule, "verifyToken").mockReturnValue({ ...mockRefreshToken, jti });

      jest.spyOn(RefreshTokenRepository.prototype, "findRefreshTokenById").mockResolvedValueOnce({ ...mockRefreshToken, revoked: false });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(false));

      // Expectations
      await expect(authService.refreshToken(refreshToken)).rejects.toThrow(AUTH_ERROR_MESSAGE.REFRESH_TOKEN_NOT_MATCHED);
      expect(sharedModule.verifyToken).toHaveBeenCalledWith(refreshToken, refreshSecret);
      expect(RefreshTokenRepository.prototype.findRefreshTokenById).toHaveBeenCalledWith(jti);
      expect(bcrypt.compare).toHaveBeenCalledWith(refreshToken, mockRefreshToken.hashedToken);
    });

    it("Return 401, when user record not found", async () => {
      // Mocks
      jest.spyOn(sharedModule, "verifyToken").mockReturnValue({ ...mockRefreshToken, jti });

      jest.spyOn(RefreshTokenRepository.prototype, "findRefreshTokenById").mockResolvedValueOnce({ ...mockRefreshToken, revoked: false });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(true));

      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ id: mockUser.id });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce(null);

      // Expectations
      await expect(authService.refreshToken(refreshToken)).rejects.toThrow(AUTH_ERROR_MESSAGE.USER_NOT_EXIST);
      expect(sharedModule.verifyToken).toHaveBeenCalledWith(refreshToken, refreshSecret);
      expect(RefreshTokenRepository.prototype.findRefreshTokenById).toHaveBeenCalledWith(jti);
      expect(bcrypt.compare).toHaveBeenCalledWith(refreshToken, mockRefreshToken.hashedToken);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        userId: mockRefreshToken.userId
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ id: mockUser.id });
    });

    it("Returns 200, when new access token is generate", async () => {
      // Mocks
      jest.spyOn(sharedModule, "verifyToken").mockReturnValue({ ...mockRefreshToken, jti });

      jest.spyOn(RefreshTokenRepository.prototype, "findRefreshTokenById").mockResolvedValueOnce({ ...mockRefreshToken, revoked: false });

      jest.spyOn(bcrypt, "compare").mockImplementationOnce(() => Promise.resolve(true));

      jest.spyOn(authService, "constructQuery").mockReturnValueOnce({ id: mockUser.id });

      jest.spyOn(AuthRepository.prototype, "findUserByAttributes").mockResolvedValueOnce({
        ...mockUser,
        password: "hashPassword",
        Profiles: {
          profilePic: "profile.png"
        }
      });

      jest.spyOn(jwtHelper, "generateAccessToken").mockReturnValueOnce({ accessToken: "newAccessToken" });

      // Expectations
      const response = await authService.refreshToken(refreshToken);
      expect(response).toBeDefined();
      expect(response).toEqual({
        accessToken: "newAccessToken",
        refreshToken
      });
      expect(sharedModule.verifyToken).toHaveBeenCalledWith(refreshToken, refreshSecret);
      expect(RefreshTokenRepository.prototype.findRefreshTokenById).toHaveBeenCalledWith(jti);
      expect(bcrypt.compare).toHaveBeenCalledWith(refreshToken, mockRefreshToken.hashedToken);
      expect(authService.constructQuery).toHaveBeenCalledWith({
        userId: mockRefreshToken.userId
      });
      expect(AuthRepository.prototype.findUserByAttributes).toHaveBeenCalledWith({ id: mockUser.id });
      expect(jwtHelper.generateAccessToken).toHaveBeenCalledWith({
        ...mockUser,
        password: "hashPassword",
        Profiles: {
          profilePic: "profile.png"
        }
      });
    });
  });
});
 */
