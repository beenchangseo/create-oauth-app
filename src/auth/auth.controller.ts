import { Body, Controller, Get, Post, Query, Req, Res, UseFilters } from '@nestjs/common';
import { AuthService } from './auth.service';
import { GetAuthorizeDto, LoginDto, PostAuthorizeDto } from './auth.dto';
import { HttpExceptionFilter } from '../middleware/filters/http-exception.filters';
import { Request, Response } from 'express';
import { SignUpDto } from '../user/user.dto';
import { UserService } from '../user/user.service';
import { CustomUnauthorizedException } from '../errors/unauthorizedException';

@Controller('auth')
@UseFilters(HttpExceptionFilter)
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly userService: UserService,
    ) {}

    @Get('authorize')
    async getAuthorize(@Query() query: GetAuthorizeDto, @Req() request: Request, @Res() response: Response) {
        const { client_id, redirect_uri, response_type, scope, state } = query;
        const loginSession = request.session.loginSessionData;

        // 로그인 세션 유무 확인
        if (!loginSession) {
            request.session.loginSessionData = {};
            request.session.loginSessionData.originalUrl = request.originalUrl;
            request.session.loginSessionData.sessionId = request.session.id;
            request.session.loginSessionData.next = 'login';
            // 로그인 페이지로 리디렉션
            return response.redirect('/auth/login');
        }

        if (loginSession.next === 'login') {
            return response.redirect('/auth/login');
        }

        // TODO: done 처리
        if (loginSession.next === 'done') {
            return response.redirect(loginSession.redirectUrl);
        }

        if (!loginSession.userId) {
            throw new CustomUnauthorizedException('Invalid user');
        }

        // 클라이언트 검증
        const client = await this.authService.getOauthClient(client_id);
        if (!client) {
            throw new CustomUnauthorizedException('Invalid client_id');
        }

        // 클라이언트의 redirect_uri 검증
        const redirectUris = client.client_redirect_uris.split(',');
        if (!redirectUris.includes(redirect_uri)) {
            throw new CustomUnauthorizedException('Invalid redirect_uri');
        }

        loginSession.clientId = client_id;
        loginSession.scope = scope;
        loginSession.responseType = response_type;
        loginSession.state = state;
        loginSession.redirectUrl = redirect_uri;
        loginSession.next = 'authorize';

        const url = new URL(redirect_uri);
        url.searchParams.append('client_id', client_id);
        url.searchParams.append('scope', scope);
        url.searchParams.append('response_type', response_type);
        url.searchParams.append('state', state);

        return response.render('authorize', {
            client_id,
            redirect_uri: url,
            scope,
            state,
            response_type,
        });
    }

    @Post('authorize')
    async postAuthorize(@Req() request: Request, @Res() response: Response, @Body() body: PostAuthorizeDto) {
        const { client_id, redirect_uri, scope, state, response_type, action } = body;
        const loginSession = request.session.loginSessionData;

        // 로그인 세션 유무 확인
        if (!loginSession) {
            throw new CustomUnauthorizedException('Invalid session');
        }

        if (loginSession.next !== 'authorize') {
            throw new CustomUnauthorizedException('Invalid session');
        }

        if (response_type !== 'code') {
            throw new CustomUnauthorizedException('Invalid response_type');
        }

        if (!loginSession.userId) {
            loginSession.originalUrl = request.originalUrl;
            return response.redirect('/auth/login');
        }

        // 클라이언트 검증
        const client = await this.authService.getOauthClient(client_id);
        if (!client) {
            throw new CustomUnauthorizedException('Invalid client_id');
        }

        // 사용자 조회
        const user = await this.userService.findUserById(loginSession.userId);
        if (!user) {
            throw new CustomUnauthorizedException('Invalid user_id');
        }

        const redirectUrl = new URL(redirect_uri);
        if (action === 'approve') {
            const authCode = await this.authService.createAuthorizationCode(loginSession.sessionId, user, client, redirect_uri, scope);

            loginSession.next = 'done';

            // 클라이언트의 redirect_uri로 리디렉션
            redirectUrl.searchParams.append('code', authCode.code);
            redirectUrl.searchParams.append('state', state);

            return response.redirect(redirectUrl.toString());
        } else {
            // 거부 시 에러 전달
            redirectUrl.searchParams.append('error', 'access_denied');
            redirectUrl.searchParams.append('state', state);

            return response.redirect(redirectUrl.toString());
        }
    }

    @Get('login')
    getLogin(@Req() request: Request, @Res() response: Response) {
        const loginSession = request.session.loginSessionData;
        if (!loginSession) {
            throw new CustomUnauthorizedException('Invalid session');
        }

        if (loginSession.next !== 'login') {
            throw new CustomUnauthorizedException('Invalid next');
        }

        return response.render('login');
    }

    @Post('login')
    async login(@Body() loginDto: LoginDto, @Req() request: Request, @Res() response: Response): Promise<void> {
        const user = await this.authService.validateUser(loginDto);
        if (user) {
            const loginSession = request.session.loginSessionData;
            if (!loginSession) {
                throw new CustomUnauthorizedException('Invalid session');
            }

            if (loginSession.next !== 'login') {
                throw new CustomUnauthorizedException('Invalid next');
            }

            const originalUrl = loginSession.originalUrl;
            if (!originalUrl) {
                throw new CustomUnauthorizedException('Invalid original_url');
            }

            loginSession.userId = user.id;
            loginSession.next = 'authorize';
            delete loginSession.originalUrl;

            return response.redirect(originalUrl);
        } else {
            return response.render('login', { error: 'Invalid credentials' });
        }
    }

    @Post('token')
    async postToken(@Req() request: Request, @Res() response: Response, @Body() body: any) {
        const authHeader = request.headers['authorization'];
        let clientId: string;
        let clientSecret: string;

        // 클라이언트 인증 (Basic Authentication)
        if (authHeader && authHeader.startsWith('Basic ')) {
            const base64Credentials = authHeader.slice(6);
            const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
            [clientId, clientSecret] = credentials.split(':');
        } else {
            return response.status(401).json({ error: 'invalid_client' });
        }

        // 클라이언트 검증
        const client = await this.authService.validateClient(clientId, clientSecret);
        if (!client) {
            return response.status(401).json({ error: 'invalid_client' });
        }

        const grantType = body.grant_type;
        console.log(`grantType = ${grantType}`);

        if (grantType === 'authorization_code') {
            const { code, redirect_uri } = body;
            const result = await this.authService.grantAuthorizationCodeProcess(client, code, redirect_uri);

            return response.status(200).json(result);
        } else if (grantType === 'refresh_token') {
            const { refresh_token } = body;
            const result = await this.authService.grantRefreshTokenProcess(client, refresh_token);

            return response.status(200).json(result);
        } else {
            return response.status(400).json({ error: 'unsupported_grant_type' });
        }
    }

    @Post('sign-up')
    async signUp(@Body() signUpDto: SignUpDto) {
        return await this.userService.createUser(signUpDto);
    }

    @Get('userinfo')
    async userInfo(@Req() request: Request) {
        const authHeader = request.headers['authorization'];
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const accessToken = authHeader.slice(7);
            const userInfo = await this.authService.getUserInfo(accessToken);

            return {
                id: userInfo.id,
                email: userInfo.email,
                name: userInfo.name,
            };
        } else {
            throw new CustomUnauthorizedException('Invalid authorization');
        }
    }
}
