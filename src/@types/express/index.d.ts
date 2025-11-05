import type * as express from "express";
import type { User } from "../../auth-server/entities/User";

declare global {
  namespace Express {
    interface Request {
      user: User;
    }
  }
}