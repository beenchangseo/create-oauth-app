import { Inject, Injectable } from '@nestjs/common';
import { OauthClient, User } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { compareSync } from 'bcrypt';
import { LoginDto } from './auth.dto';
import { REDIS_CLIENT } from '../utils/cache/cache.providers';
import { Redis } from 'ioredis';

type AuthorizationCode = {
    sessionId: string;
    code: string;
    user: User;
    client: OauthClient;
    redirect_uri: string;
    expired_at: number;
    scope: string;
};

type AccessToken = {
    token: string;
    user_id: string;
    expired_at: number;
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

    async validateClient(clientId: string, clientSecret: string): Promise<OauthClient> {
        const client = await this.prismaService.oauthClient.findUnique({ where: { client_id: clientId } });
        if (client && client.client_secret === clientSecret) {
            return client;
        }
        return null;
    }

    // 권한 부여 코드 검증
    async validateAuthorizationCode(
        code: string,
        client: OauthClient,
        redirectUri: string,
    ): Promise<AuthorizationCode> {
        const authCode: AuthorizationCode = JSON.parse(await this.redisClient.get(`oauth-authorization-code-${code}`));

        if (
            authCode &&
            authCode.client.id === client.id &&
            authCode.redirect_uri === redirectUri &&
            authCode.expired_at > Date.now() &&
            authCode.code === code
        ) {
            return authCode;
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
        sessionId: string,
        user: User,
        client: OauthClient,
        redirectUri: string,
        scope: string,
    ): Promise<AuthorizationCode> {
        const code = this.generateRandomString(32);
        const authorizationCode: AuthorizationCode = {
            sessionId,
            code,
            user: user,
            client: client,
            redirect_uri: redirectUri,
            expired_at: Date.now() + 600000, // 10분 후 만료
            scope: scope,
        };

        await this.redisClient.setex(`oauth-authorization-code-${code}`, 600, JSON.stringify(authorizationCode));

        return authorizationCode;
    }

    async deleteAuthorizationCode(code: string): Promise<void> {
        await this.redisClient.del(`oauth-authorization-code-${code}`);
    }

    async deleteLoginSession(sessionId: string) {
        await this.redisClient.del(`oauth-session-${sessionId}`);
    }

    // 액세스 토큰 생성
    async createAccessToken(user: User, client: OauthClient, scope: string): Promise<AccessToken> {
        const token = this.generateRandomString(64);
        const accessToken: AccessToken = {
            token,
            user_id: user.id,
            expired_at: Date.now() + 3600000, // 1시간 후 만료
            scope,
        };

        await this.redisClient.setex(`access-token-${token}`, 60 * 60, JSON.stringify(accessToken));

        return accessToken;
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
