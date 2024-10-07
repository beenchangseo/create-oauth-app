import { Inject, Injectable } from '@nestjs/common';
import { OauthClient, User } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { compareSync } from 'bcrypt';
import { LoginDto } from './auth.dto';
import { REDIS_CLIENT } from '../utils/cache/cache.providers';
import { Redis } from 'ioredis';
import { ConfigService } from '@nestjs/config';
import { CustomUnauthorizedException } from '../errors/unauthorizedException';
import { UserService } from 'src/user/user.service';

type AuthorizationCode = {
    sessionId: string;
    code: string;
    user: User;
    client: OauthClient;
    redirect_uri: string;
    expired_at: number;
    scope: string;
};

type RefreshTokenData = {
    clientId: string;
    sessionId: string;
    userId: string;
    grantType: string;
    scope: string;
    loginTime: number;
};

type AccessTokenData = {
    accessToken: string;
    refreshToken: string;
    userId: string;
    expiredIn: number;
    scope: string;
};

type PostTokenResponse = {
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
    scope: string;
};

@Injectable()
export class AuthService {
    private accessTokenTtl: number;
    private refreshTokenTtl: number;
    private sessionTtl: number;

    constructor(
        private readonly prismaService: PrismaService,
        @Inject(REDIS_CLIENT) private readonly redisClient: Redis,
        private readonly configService: ConfigService,
        private readonly userService: UserService,
    ) {
        this.accessTokenTtl = parseInt(this.configService.get<string>('ACCESS_TOKEN_TTL'));
        this.refreshTokenTtl = parseInt(this.configService.get<string>('REFRESH_TOKEN_TTL'));
        this.sessionTtl = parseInt(this.configService.get<string>('SESSION_TTL'));
    }

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
    private async validateAuthorizationCode(code: string, client: OauthClient, redirectUri: string): Promise<AuthorizationCode> {
        const authCode: AuthorizationCode = JSON.parse(await this.redisClient.get(`oauth-authorization-code-${code}`));

        if (
            authCode &&
            authCode.client.id === client.id &&
            // authCode.redirect_uri === redirectUri &&
            // redirectUri.includes(authCode.redirect_uri) &&
            authCode.expired_at > Date.now() &&
            authCode.code === code
        ) {
            return authCode;
        }

        return null;
    }

    private async validateRefreshToken(client: OauthClient, refreshToken: string): Promise<RefreshTokenData> {
        const tokenResult = await this.redisClient.get(`refreshtoken:token:${refreshToken}`);
        if (!tokenResult) {
            return null;
        }

        const refreshTokenData: RefreshTokenData = JSON.parse(tokenResult);
        if (refreshTokenData.clientId !== client.client_id) {
            return null;
        }

        const session = await this.redisClient.get(`oauth-session-${refreshTokenData.sessionId}`);
        if (!session) {
            return null;
        }

        const userIdResult = await this.redisClient.get(`refreshtoken:userId:${refreshTokenData.userId}`);
        if (!userIdResult || userIdResult !== refreshToken) {
            return null;
        }

        return refreshTokenData;
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

    private async deleteAuthorizationCode(code: string): Promise<void> {
        await this.redisClient.del(`oauth-authorization-code-${code}`);
    }

    private async deleteLoginSession(sessionId: string): Promise<void> {
        const session = JSON.parse(await this.redisClient.get(`oauth-session-${sessionId}`));
        delete session.loginSessionData;
        await this.redisClient.setex(`oauth-session-${sessionId}`, this.sessionTtl, JSON.stringify(session));
    }

    private async createRefreshToken(authCode: AuthorizationCode): Promise<string> {
        const refreshToken = this.generateRandomString(64);
        const userId = authCode.user.id;

        // 신규 발행하는경우 기존 데이터는 만료처리
        const oldRefreshToken = await this.redisClient.get(`refreshtoken:userId:${userId}`);
        if (oldRefreshToken) {
            await this.redisClient.del(`refreshtoken:token:${oldRefreshToken}`);
            await this.redisClient.del(`refreshtoken:userId:${userId}`);
        }

        const refreshTokenData: RefreshTokenData = {
            clientId: authCode.client.client_id,
            sessionId: authCode.sessionId,
            userId,
            grantType: 'authorization_code',
            scope: authCode.scope,
            loginTime: Date.now(),
        };

        await this.redisClient.setex(`refreshtoken:token:${refreshToken}`, this.refreshTokenTtl, JSON.stringify(refreshTokenData));
        await this.redisClient.setex(`refreshtoken:userId:${userId}`, this.refreshTokenTtl, refreshToken);

        return refreshToken;
    }

    // 액세스 토큰 생성
    private async createAccessToken(userId: string, scope: string, refreshToken: string): Promise<AccessTokenData> {
        const accessToken = this.generateRandomString(64);
        const accessTokenData: AccessTokenData = {
            accessToken,
            refreshToken,
            userId,
            expiredIn: this.accessTokenTtl,
            scope,
        };

        await this.redisClient.setex(`accesstoken:token:${accessToken}`, this.accessTokenTtl, JSON.stringify(accessTokenData));

        return accessTokenData;
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

    async grantAuthorizationCodeProcess(client: OauthClient, code: string, redirectUri: string): Promise<PostTokenResponse> {
        // 권한 부여 코드 검증
        const authCode = await this.validateAuthorizationCode(code, client, redirectUri);
        if (!authCode) {
            throw new CustomUnauthorizedException('Invalid grant');
        }

        // refresh 토큰 생성
        const refreshToken = await this.createRefreshToken(authCode);

        // access 토큰 생성
        const accessToken = await this.createAccessToken(authCode.user.id, authCode.scope, refreshToken);

        // 권한 부여 코드 삭제
        await this.deleteAuthorizationCode(authCode.code);

        // oauth 로그인 세션 데이터 삭제
        await this.deleteLoginSession(authCode.sessionId);

        // 응답 반환
        return {
            access_token: accessToken.accessToken,
            refresh_token: refreshToken,
            token_type: 'Bearer',
            expires_in: accessToken.expiredIn,
            scope: accessToken.scope,
        };
    }

    async grantRefreshTokenProcess(client: OauthClient, refreshToken: string): Promise<PostTokenResponse> {
        // refresh 토큰 검증
        const validRefreshToken = await this.validateRefreshToken(client, refreshToken);
        if (!validRefreshToken) {
            throw new CustomUnauthorizedException('Invalid grant');
        }

        // access 토큰 생성
        const accessToken = await this.createAccessToken(validRefreshToken.userId, validRefreshToken.scope, refreshToken);

        // 응답 반환
        return {
            access_token: accessToken.accessToken,
            refresh_token: refreshToken,
            token_type: 'Bearer',
            expires_in: accessToken.expiredIn,
            scope: accessToken.scope,
        };
    }

    async getUserInfo(accessToken: string): Promise<User> {
        const data: AccessTokenData = JSON.parse(await this.redisClient.get(`accesstoken:token:${accessToken}`));
        if (!data) {
            throw new CustomUnauthorizedException('Invalid authorization');
        }

        const user = await this.userService.findUserById(data.userId);

        return user;
    }
}
