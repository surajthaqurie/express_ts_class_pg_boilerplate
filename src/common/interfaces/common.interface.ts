export interface IDbBaseProperties {
  id: string;
  status: boolean;
  deleted: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface IUserJWTInfo {
  id: string;
  role: string;
}

export interface IAuthJWTRequest extends Request {
  user: IUserJWTInfo;
}

export interface IPaginationResponse<T> {
  data: T[];
  totalCount: number;
}
