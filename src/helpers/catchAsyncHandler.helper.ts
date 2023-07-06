import { Request, Response, NextFunction } from "express";

export const catchAsyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    fn(req, res, next).catch(next);
  };
};
