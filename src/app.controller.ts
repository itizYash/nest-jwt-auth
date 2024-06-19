import { BadRequestException, Body, Controller, Get, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { AppService } from './app.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Request, Response, response } from 'express';

@Controller('api')
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly jwtService: JwtService
  ) { }

  // REGISTER
  @Post('register')
  async register(
    @Body('name') name: string,
    @Body('email') email: string,
    @Body('password') password: string
  ) {
    const hashedPassword = await bcrypt.hash(password, 12);
    try {
      // Check if user with the same email already exists
      const existingUser = await this.appService.findUser({ where: { email } });
      if (existingUser) {
        return { success: false, message: 'Email already exists' };
      }
      const user = await this.appService.create({
        name,
        email,
        password: hashedPassword
      });
      delete user.password;
      return user;
    } catch (error) {
      return { success: false, message: 'Failed to register user' };
    }

  }

  // LOGIN
  @Post('login')
  async login(
    @Body('email') email: string,
    @Body('password') password: string,
    @Res({ passthrough: true }) response: Response
  ) {
    const user = await this.appService.findUser({ where: { email } });
    if (!user) {
      throw new BadRequestException('invalid credentials');
    }
    if (!await bcrypt.compare(password, user.password)) {
      throw new BadRequestException('invalid credentials');
    }
    const jwt = await this.jwtService.signAsync({ id: user.id });
    response.cookie('jwt', jwt, { httpOnly: true })
    delete user.password;
    return { success: true, user: user };
  }

  // GET USER
  @Get('user')
  async user(@Req() request: Request) {
    try {
      const cookie = request.cookies['jwt'];
      const data = await this.jwtService.verifyAsync(cookie);
      if (!data) {
        throw new UnauthorizedException();
      }
      const user = await this.appService.findUser({ where: { id: data['id'] } });
      const { password, ...result } = user;
      return result;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  // LOGOUT
  @Post('logout')
  async logout(@Res({passthrough:true}) response: Response){
    response.clearCookie('jwt');
    return {success: true,message:"Successfully Logout"}
  }
}
