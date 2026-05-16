import { Body, Controller, Get, Post, Req, UseGuards } from "@nestjs/common";
import { IsEmail, IsString, MinLength } from "class-validator";
import { AuthGuard } from "./auth.guard";
import { AuthService } from "./auth.service";

class LoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  password!: string;
}

@Controller("/api/auth")
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post("/login")
  login(@Body() body: LoginDto) {
    return this.auth.login(body.email, body.password);
  }

  @Get("/me")
  @UseGuards(AuthGuard)
  me(@Req() req: any) {
    return { user: req.user };
  }
}
