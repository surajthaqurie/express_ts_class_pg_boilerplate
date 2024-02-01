/* 
import { v4 as uuidv4 } from "uuid"
import { prisma } from "src/helpers"
import { AuthRepository } from "../auth.repository"
import {
  AuthInvitationCodeProducer,
  AuthUserProducer
} from "src/events/producer"
import { logger } from "@sharedModule/chat-app"
import { SessionRepository } from "src/modules/session"
import { AUTH_REPOSITORY_ERROR_MESSAGES } from "../auth.constant"


jest.mock("src/events/producer")
jest.mock("@sharedModule/chat-app")
jest.mock("src/helpers", () => {
  const actualHelpers = jest.requireActual("src/helpers")


  return {
    ...actualHelpers,
    prisma: {
      ...actualHelpers.prisma,
      $transaction: jest.fn(),
      users: {
        ...actualHelpers.prisma.users,
        create: jest.fn(),
        findFirst: jest.fn(),
        count: jest.fn(),
        findMany: jest.fn()
      },
      invitationTrackers: {
        ...actualHelpers.prisma.invitationTrackers,
        update: jest.fn()
      }
    }
  }
})


let authRepository: AuthRepository


describe("AuthRepository.", () => {
  beforeEach(() => {
    authRepository = new AuthRepository()
  })


  const mockUser = {
    id: uuidv4(),
    fullname: "Naomi Garcia",
    username: "garcia_1",
    email: "garcia101@yopmail.com",
    countryCode: "+977",
    phoneNumber: "1234567890",
    isDeleted: false,
    resetPasswordExpiration: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
    Profiles: {}
  }


  afterEach(() => {
    jest.clearAllMocks()
    jest.resetModules()
  })


  describe("Create, produce user and revoked Invitation code.", () => {
    // Mock the SignupPayload
    const signupPayload = {
      username: mockUser.username,
      email: mockUser.email,
      password: "P@ssw0rd#",
      fullname: mockUser.fullname,
      phoneNumber: mockUser.phoneNumber,
      invitationCode: "DRW45O"
    }
    it("Returns 400, user is not updated created.", async () => {
      const mockError = new Error(
        "Unable to Create produce and revoked invitation code."
      )


      jest.spyOn(prisma, "$transaction").mockRejectedValueOnce(mockError)


      try {
        await authRepository.createProduceUserAndRevokedInvitationCode(
          signupPayload
        )
      } catch (error) {
        // Expectations
        expect(error).toBe(mockError)
        expect(logger.error).toHaveBeenCalledWith(
          AUTH_REPOSITORY_ERROR_MESSAGES.UNABLE_TO_CREATE_AND_PRODUCE_USER_AND_PROFILE,
          mockError
        )
      }


      // Expectations
      expect(prisma.$transaction).toHaveBeenCalledTimes(1)
      expect(logger.error).toHaveBeenCalledTimes(1)
    })


    it("Returns 200, when user is created successfully and produce the user and revoked invitation code.", async () => {
      // mock prisma transaction
      jest.spyOn(prisma, "$transaction").mockImplementationOnce(async () => {
        jest
          .spyOn(prisma.users, "create")
          .mockResolvedValueOnce({ ...mockUser, password: "hahsPassword" })
        jest.spyOn(prisma.invitationTrackers, "update").mockResolvedValueOnce({
          id: "test",
          isUsed: true,
          invitationCode: signupPayload.invitationCode
        })


        jest.spyOn(AuthUserProducer.prototype, "send")
        jest.spyOn(AuthInvitationCodeProducer.prototype, "send")


        return mockUser
      })


      const response =
        await authRepository.createProduceUserAndRevokedInvitationCode(
          signupPayload
        )


      // Expectations
      expect(response).toBeDefined()
      expect(response).toEqual(mockUser)
      expect(prisma.$transaction).toHaveBeenCalledTimes(1)
    })
  })


  describe("Get user details.", () => {
    it("Returns 400, when user record not found.", async () => {
      jest.spyOn(prisma.users, "findFirst").mockResolvedValueOnce(null)


      // Expectations
      const user = await authRepository.getUsersDetails(mockUser.id)


      expect(user).toBeNull()
    })


    it("Returns 200, when user record found", async () => {
      jest
        .spyOn(prisma.users, "findFirst")
        .mockResolvedValueOnce({ ...mockUser, password: "hashPassword" })


      // Expectations
      const user = await authRepository.getUsersDetails(mockUser.id)


      expect(user).toBeDefined()
      expect(user).toEqual({ ...mockUser, password: "hashPassword" })
    })
  })


  describe("Find user by attributes.", () => {
    const searchQuery = { email: mockUser.email }


    it("Returns 400, when user record not found.", async () => {
      jest.spyOn(prisma.users, "findFirst").mockResolvedValueOnce(null)


      // Expectations
      const user = await authRepository.findUserByAttributes(searchQuery)


      expect(user).toBeNull()
    })


    it("Returns 200, when user record found", async () => {
      jest
        .spyOn(prisma.users, "findFirst")
        .mockResolvedValueOnce({ ...mockUser, password: "hashPassword" })


      // Expectations
      const user = await authRepository.findUserByAttributes(searchQuery)


      expect(user).toBeDefined()
      expect(user).toEqual({ ...mockUser, password: "hashPassword" })
      expect(prisma.users.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { ...searchQuery, isDeleted: false }
        })
      )
    })
  })


  describe("Search Friends.", () => {
    const pageSize = 1
    const offset = 10
    const searchQuery = { id: { not: mockUser.id } }


    it("Returns 200, when have no friends.", async () => {
      jest.spyOn(prisma, "$transaction").mockResolvedValueOnce([0, []])


      const { users, totalCount } = await authRepository.searchFriends(
        searchQuery,
        pageSize,
        offset
      )


      // Expectations
      expect(users).toHaveLength(0)
      expect(totalCount).toEqual(0)


      expect(prisma.$transaction).toHaveBeenCalledWith([
        prisma.users.count(
          expect.objectContaining({
            where: { ...searchQuery, isDeleted: false }
          })
        ),
        prisma.users.findMany(
          expect.objectContaining({
            where: { ...searchQuery, isDeleted: false },
            take: pageSize,
            skip: offset
          })
        )
      ])
    })


    it("Returns 200, when have friends.", async () => {
      jest.spyOn(prisma, "$transaction").mockResolvedValueOnce([10, [mockUser]])


      const { users, totalCount } = await authRepository.searchFriends(
        searchQuery,
        pageSize,
        offset
      )


      // Expectations
      expect(users).toEqual(
        expect.arrayContaining([expect.objectContaining(mockUser)])
      )
      expect(totalCount).toEqual(10)


      expect(prisma.$transaction).toHaveBeenCalledWith([
        prisma.users.count(
          expect.objectContaining({
            where: { ...searchQuery, isDeleted: false }
          })
        ),
        prisma.users.findMany(
          expect.objectContaining({
            where: { ...searchQuery, isDeleted: false },
            take: pageSize,
            skip: offset
          })
        )
      ])
    })
  })


  describe("Updates and produce password and Revoked Token.", () => {
    const mockPayload = {
      password: "hashedPassword",
      id: mockUser.id
    }


    it("Returns 400, when unable to update password and revoked token.", async () => {
      const mockError = new Error(
        "Unable to update password and revoked token."
      )


      jest.spyOn(prisma, "$transaction").mockRejectedValueOnce(mockError)


      try {
        await authRepository.updateAndProducePasswordAndRevokedToken(
          mockPayload.password,
          mockPayload.id
        )
      } catch (error) {
        // Expectations
        expect(error).toBe(mockError)
        expect(logger.error).toHaveBeenCalledWith(
          AUTH_REPOSITORY_ERROR_MESSAGES.UNABLE_TO_UPDATE_AND_PRODUCE_PASSWORD_AND_REVOKED_TOKEN,
          mockError
        )
      }


      // Expectations
      expect(prisma.$transaction).toHaveBeenCalledTimes(1)
      expect(logger.error).toHaveBeenCalledTimes(1)
    })


    it("Returns 200, when password and revoked token is updated.", async () => {
      // mock prisma transaction
      jest.spyOn(prisma, "$transaction").mockImplementationOnce(async () => {
        jest
          .spyOn(prisma.users, "update")
          .mockResolvedValueOnce({ ...mockUser, password: "hashPassword" })
        jest.spyOn(AuthUserProducer.prototype, "send")


        return mockUser.id
      })


      jest.spyOn(SessionRepository.prototype, "deleteRecords")


      await authRepository.updateAndProducePasswordAndRevokedToken(
        mockPayload.password,
        mockPayload.id
      )
      // Expectations
      // expect(prisma.$transaction).toHaveBeenCalledTimes(1)
      expect(SessionRepository.prototype.deleteRecords).toHaveBeenCalledTimes(1)
      expect(
        SessionRepository.prototype.deleteRecords
      ).toHaveBeenLastCalledWith(mockPayload.id)
      expect(logger.info).toHaveBeenCalledWith(
        "Successfully deleted the session record."
      )
    })
  })


  describe("Remove Reset OTP.", () => {
    it("Returns 200, when user opt are removed.", async () => {
      jest
        .spyOn(prisma.resetOtpTracker, "deleteMany")
        .mockResolvedValueOnce({ count: 1 })


      const response = await authRepository.removeResetOtp(mockUser.id)


      // Expectations
      expect(response).toBeDefined()
      expect(response).toEqual({ count: 1 })
      expect(prisma.resetOtpTracker.deleteMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: { userId: mockUser.id }
        })
      )
    })
  })


  describe("Update and reset password expiration.", () => {
    it("Returns 400, when unable to update reset password expiration.", async () => {
      const mockError = new Error("unable to update reset password expiration.")


      jest.spyOn(prisma, "$transaction").mockImplementationOnce(() => {
        throw mockError
      })


      try {
        await authRepository.updateResetPasswordExpiration(
          mockUser.id,
          new Date()
        )
      } catch (error) {
        // Expectations
        expect(error).toBe(mockError)
        expect(logger.error).toHaveBeenCalledWith(
          AUTH_REPOSITORY_ERROR_MESSAGES.UNABLE_TO_UPDATE_AND_PRODUCE_RESET_PASSWORD_EXPIRATION,
          mockError
        )
      }


      // Expectations
      expect(prisma.$transaction).toHaveBeenCalledTimes(1)
      expect(logger.error).toHaveBeenCalledTimes(1)
    })


    it("Returns 200, when user reset password expiration is updated.", async () => {
      const updatedUser = {
        ...mockUser,
        password: "hashPassword",
        resetPasswordExpiration: new Date(
          new Date().getTime() + 1000 * 60 * 60 * 1
        )
      }
      jest.spyOn(prisma, "$transaction").mockImplementationOnce(async () => {
        jest.spyOn(prisma.users, "update").mockResolvedValueOnce(updatedUser)
        jest.spyOn(AuthUserProducer.prototype, "send")


        return updatedUser
      })


      const response = await authRepository.updateResetPasswordExpiration(
        mockUser.id,
        new Date()
      )


      // Expectations
      expect(response).toBeDefined()
      expect(response).toEqual(updatedUser)
      expect(prisma.$transaction).toHaveBeenCalledTimes(1)
    })
  })
})
 */
