import { Request, Response } from "express";
import { container } from "tsyringe";

import { UpdateUserAvatarUseCase } from "./UpdateUserAvatarUseCase";

class UpdateUserAvatarController {
  async handle(request: Request, response: Response): Promise<Response> {
    const { id } = request.user;

    const avatarFile = request.file.filename;

    container.resolve(UpdateUserAvatarUseCase);
    const updateUserAvatarUsecase = container.resolve(UpdateUserAvatarUseCase);

    await updateUserAvatarUsecase.execute({ user_id: id, avatarFile });

    return response.status(204).send();
  }
}

export { UpdateUserAvatarController };
