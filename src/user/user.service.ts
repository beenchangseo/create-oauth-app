import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignUpDto } from './user.dto';
import { User } from '@prisma/client';
import { genSalt, genSaltSync, hash, hashSync } from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly configService: ConfigService,
    ) {}

    async createUser(signUpDto: SignUpDto): Promise<User> {
        const saltRound = this.configService.get<string>('PASSWORD_SALT');
        const salt = genSaltSync(parseInt(saltRound));
        const hashPassword = hashSync(signUpDto.password, salt);
        signUpDto.password = hashPassword;

        return await this.prismaService.user.create({ data: signUpDto });
    }

    async findUserById(userId: string): Promise<User> {
        return await this.prismaService.user.findUnique({ where: { id: userId } });
    }
}
