import { NextFunction, Request, Response } from "express";
import { verify } from "jsonwebtoken";

import { AppError } from "../errors/AppError";
import { UsersRepository } from "../modules/accounts/repositories/implementations/UsersRepository";

interface IPayload {
  id: string;
}

export async function ensureAuthenticated(
  request: Request,
  response: Response,
  next: NextFunction
) {
  const authHeader = request.headers.authorization;

  if (!authHeader) throw new AppError("Token is missing", 401);

  const [bearer, token] = authHeader.split(" ");

  try {
    const { id } = verify(
      token,
      "04aa9e199a08bd961f76bf9e0a0420bd"
    ) as IPayload;

    const usersRepository = new UsersRepository();

    const user = usersRepository.findById(id);

    if (!user) throw new AppError("User does not exists", 401);

    next();
  } catch {
    throw new AppError("Invalid token", 401);
  }
}
