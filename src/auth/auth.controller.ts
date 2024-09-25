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
            // 로그인 페이지로 리디렉션
            return response.redirect('/auth/login');
        }

        // 사용자 로그인 여부 확인
        if (!loginSession.userId) {
            // 로그인 페이지로 리디렉션
            return response.redirect('/auth/login');
        }

        if (loginSession.next !== 'login-request') {
            if (loginSession.next === 'authorize') {
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
            } else {
                // todo
            }
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
            throw new CustomUnauthorizedException('Invalid session(no session)');
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
            const authCode = await this.authService.createAuthorizationCode(
                loginSession.sessionId,
                user,
                client,
                redirect_uri,
                scope,
            );

            // 클라이언트의 redirect_uri로 리디렉션
            redirectUrl.searchParams.append('code', authCode.code);
            if (state) {
                redirectUrl.searchParams.append('state', state);
            }

            return response.redirect(redirectUrl.toString());
        } else {
            // 거부 시 에러 전달
            redirectUrl.searchParams.append('error', 'access_denied');
            if (state) redirectUrl.searchParams.append('state', state);

            return response.redirect(redirectUrl.toString());
        }
    }

    @Get('login')
    getLogin(@Res() res: Response) {
        return res.render('login');
    }

    @Post('login')
    async login(@Body() loginDto: LoginDto, @Req() request: Request, @Res() response: Response): Promise<void> {
        const user = await this.authService.validateUser(loginDto);
        if (user) {
            const loginSession = request.session.loginSessionData;
            if (loginSession == null) {
                // 세션이 삭제된 경우 처리
                throw new CustomUnauthorizedException('');
            }

            loginSession.userId = user.id;
            loginSession.next = 'login-request';

            const redirectUrl = loginSession.originalUrl || '/';
            delete loginSession.originalUrl;

            return response.redirect(redirectUrl);
        } else {
            return response.render('login', { error: 'Invalid credentials' });
        }
    }

    @Post('token')
    async postToken(@Req() request: Request, @Res() response: Response, @Body() body: any) {
        console.log(request.session.loginSessionData);

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

        const { grant_type, code, redirect_uri } = body;

        if (grant_type === 'authorization_code') {
            // 권한 부여 코드 검증
            const authCode = await this.authService.validateAuthorizationCode(code, client, redirect_uri);
            if (!authCode) {
                return response.status(400).json({ error: 'invalid_grant' });
            }

            // 액세스 토큰 생성
            const accessToken = await this.authService.createAccessToken(authCode.user, client, authCode.scope);

            // 권한 부여 코드 삭제
            await this.authService.deleteAuthorizationCode(authCode.code);

            // oauth 로그인 세션 삭제
            await this.authService.deleteLoginSession(authCode.sessionId);

            // 응답 반환
            return response.json({
                access_token: accessToken.token,
                token_type: 'Bearer',
                expires_in: 3600,
                scope: accessToken.scope,
            });
        } else {
            return response.status(400).json({ error: 'unsupported_grant_type' });
        }
    }

    @Post('sign-up')
    async signUp(@Body() signUpDto: SignUpDto) {
        return await this.userService.createUser(signUpDto);
    }
}
