import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { ConfigModule } from '@nestjs/config';

@Module({
    imports: [UserModule, ConfigModule],
    controllers: [AuthController],
    providers: [AuthService],
})
export class AuthModule {}
