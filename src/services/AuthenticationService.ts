import { Repository } from "typeorm";
import { User } from "../entities/User";
import jwt from "jsonwebtoken";
import { InvalidCredentialsError, InvalidRefreshTokenError, NotFoundError } from "../errors";
import { createDatabaseConnection } from "../database";

export class AuthenticationService {
  constructor(private userRepository: Repository<User>) { }

  async login(email: string, password: string): Promise<{ access_token: string, refresh_token: string }> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user || !user.comparePassword(password)) {
      throw new InvalidCredentialsError();
    }
    return {
      access_token: AuthenticationService.generateAccessToken(user),
      refresh_token: AuthenticationService.generateRefreshToken(user)
    };
  }

  static generateAccessToken(user: User): string {
    return jwt.sign(
      { name: user.name, email: user.email },
      process.env.JWT_PRIVATE_KEY as string,
      { expiresIn: process.env.JWT_ACCESS_TOKEN_EXPIRES_IN as any, 
        subject: user.id.toString(),
        algorithm: "RS256"
      }
    );
  }

  static generateRefreshToken(user: User): string {
    return jwt.sign(
      { name: user.name, email: user.email },
      process.env.JWT_PRIVATE_KEY as string,
      { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRES_IN as any, 
        subject: user.id.toString(),
        algorithm: "RS256"
      }
    );
  }

  static verifyAccessToken(token: string): {
    sub: string;
    name: string;
    email: string;
    iat: number;
    exp: number;
  } {
    return jwt.verify(token, process.env.JWT_PUBLIC_KEY as string, {
      algorithms: ["RS256"]
    }) as {
      sub: string;
      name: string;
      email: string;
      iat: number;
      exp: number;
    };
  }

  static verifyRefreshToken(token: string): {
    sub: string;
    name: string;
    email: string;
    iat: number;
    exp: number;
  } {
    return jwt.verify(token, process.env.JWT_PUBLIC_KEY as string, {
      algorithms: ["RS256"]
    }) as {
      sub: string;
      name: string;
      email: string;
      iat: number;
      exp: number;
    };
  }

  async refreshToken(refreshToken: string): Promise<{ access_token: string, refresh_token: string }> {
    try {
      const payload = AuthenticationService.verifyRefreshToken(refreshToken);
      const user = await this.userRepository.findOne({ where: { id: +payload.sub } });
      if (!user) {
        throw new NotFoundError({ message: 'User not found' });
      }
      return {
        access_token: AuthenticationService.generateAccessToken(user),
        refresh_token: AuthenticationService.generateRefreshToken(user)
      };
    } catch (error) {
      console.error(error);
      throw new InvalidRefreshTokenError({ options: { cause: error } });
    }
  }
}

export async function createAuthenticationService(): Promise<AuthenticationService> {
  const { userRepository } = await createDatabaseConnection();
  return new AuthenticationService(userRepository);
}