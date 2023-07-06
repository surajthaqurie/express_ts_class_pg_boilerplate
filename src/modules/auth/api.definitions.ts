import { AUTH_MESSAGE_CONSTANT } from "src/common/constants";

export default {
  server: {
    tags: [
      {
        name: "Auth",
        description: "Api for authentication"
      }
    ],

    paths: {
      "/auth/signup": {
        post: {
          tags: ["Auth"],
          summary: "User signup api.",
          description: "Api for user signup.",
          operationId: "signup",
          requestBody: {
            description: "Payload for signup.",
            required: true,
            content: {
              "application/json": {
                schema: {
                  $ref: "#/components/schemas/SignupRequest"
                }
              }
            }
          },
          responses: {
            201: {
              description: "",
              content: {
                "application/json": {
                  schema: {
                    $ref: "#/components/schemas/SignupResponse"
                  }
                }
              }
            },
            409: {
              description: "",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: {
                        type: "boolean",
                        example: false
                      },
                      message: {
                        type: "string",
                        example: AUTH_MESSAGE_CONSTANT.EMAIL_ALREADY_TAKEN
                      }
                    }
                  }
                }
              }
            },
            400: {
              description: "",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      success: {
                        type: "boolean",
                        example: false
                      },
                      message: {
                        type: "string",
                        example: AUTH_MESSAGE_CONSTANT.UNABLE_TO_CREATE_USER
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    components: {
      schemas: {
        SignupRequest: {
          type: "object",
          properties: {
            firstName: {
              type: "string",
              required: true,
              example: "suraj"
            },
            lastName: {
              type: "string",
              required: true,
              example: "chand"
            },
            username: {
              type: "string",
              required: true,
              example: "suraj12"
            },
            password: {
              type: "string",
              required: true,
              example: "Player@123"
            },
            confirmPassword: {
              type: "string",
              required: true,
              example: "Player@123"
            },
            email: {
              type: "string",
              required: true,
              example: "devlop143@gmail.com"
            },
            phone: {
              type: "string",
              required: true,
              example: "0000000000"
            }
          }
        },
        SignupResponse: {
          type: "object",
          properties: {
            success: {
              type: "boolean",
              example: true
            },
            message: {
              type: "string",
              example: AUTH_MESSAGE_CONSTANT.USER_CREATED_SUCCESSFULLY
            },
            data: {
              type: "object",
              properties: {
                id: {
                  type: "string",
                  example: "84012b1e-900b-4ff7-bcff-d1dad341abdf"
                },
                firstName: {
                  type: "string",
                  example: "Suraj"
                },
                lastName: {
                  type: "string",
                  example: "Chand"
                },
                email: {
                  type: "string",
                  example: "devlop143@gmail.com"
                },
                username: {
                  type: "string",
                  example: "suraj12"
                },
                phone: {
                  type: "string",
                  example: "0000000000"
                },
                avatar: {
                  type: "string",
                  example: null
                },
                createdAt: {
                  type: "string",
                  example: "2023-06-18T17:35:47.699Z"
                },
                updatedAt: {
                  type: "string",
                  example: "2023-06-18T17:35:47.699Z"
                }
              }
            }
          }
        }
      }
    }
  }
};
