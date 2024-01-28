import type { Config } from "jest";

const config: Config = {
  verbose: true,
  preset: "ts-jest",
  testEnvironment: "node",

  testMatch: ["**/__tests__/**/*.[jt]s?(x)", "**/?(*.)+(spec|test).[tj]s?(x)"],
  testPathIgnorePatterns: ["/node_modules/", "/build/"],
  transform: { "^.+\\.(ts|tsx)$": "ts-jest" },
  // collectCoverage: true,
  // coveragePathIgnorePatterns: ["/node_modules/"],
  // coverageDirectory: "./coverage",

  resetMocks: true,
  clearMocks: true,

  moduleNameMapper: {
    "@/(.*)": "<rootDir>/src/$1"
  }
};

export default config;
