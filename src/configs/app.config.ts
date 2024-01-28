import { dotEnv as env } from "../common/utils";

export default {
  appConfig: {
    PORT: env.PORT,
    APP_URL: env.APP_URL,
    NODE_ENV: env.NODE_ENV,
    APP_NAME: env.APP_NAME
  },
  dbConfig: {
    DATABASE_URL: env.DATABASE_URL
  }
};
