import { Inject, Injectable } from '@nestjs/common';
import { OauthClient, User } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { compareSync } from 'bcrypt';
import { LoginDto } from './auth.dto';
import { v4 as uuidV4 } from 'uuid';
import { REDIS_CLIENT } from '../utils/cache/cache.providers';
import { Redis } from 'ioredis';

type AuthorizationCode = {
    id: string;
    code: string;
    user: User;
    client: OauthClient;
    redirectUri: string;
    expiresAt: Date;
    scope: string;
};

@Injectable()
export class AuthService {
    constructor(
        private readonly prismaService: PrismaService,
        @Inject(REDIS_CLIENT) private readonly redisClient: Redis,
    ) {}

    async validateUser(loginDto: LoginDto): Promise<User> {
        const user = await this.prismaService.user.findUnique({
            where: {
                email: loginDto.email,
            },
        });

        if (user && compareSync(loginDto.password, user.password)) {
            return user;
        }

        return null;
    }

    async getOauthClient(clientId: string): Promise<OauthClient> {
        return await this.prismaService.oauthClient.findUnique({
            where: { client_id: clientId },
        });
    }

    // 권한 부여 코드 생성
    async createAuthorizationCode(
        user: User,
        client: OauthClient,
        redirectUri: string,
        scope: string,
    ): Promise<AuthorizationCode> {
        const authorizationCode: AuthorizationCode = {
            id: uuidV4(),
            code: this.generateRandomString(32),
            user: user,
            client: client,
            redirectUri: redirectUri,
            expiresAt: new Date(Date.now() + 600000), // 10분 후 만료
            scope: scope,
        };

        await this.redisClient.setex(`oauth-authorization-code`, 600000, JSON.stringify(authorizationCode));

        return authorizationCode;
    }

    // 랜덤 문자열 생성
    generateRandomString(length: number): string {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
}
