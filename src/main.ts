import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from './middleware/pipes/validation.pipe';
import { HttpExceptionFilter } from './middleware/filters/http-exception.filters';
import RedisStore from 'connect-redis';
import * as session from 'express-session';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from './utils/cache/cache.providers';
import { ConfigService } from '@nestjs/config';
import * as passport from 'passport';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';

declare module 'express-session' {
    interface SessionData {
        loginSessionData: {
            sessionId?: string;
            userId?: string;
            clientId?: string;
            scope?: string;
            responseType?: string;
            state?: string;
            next?: 'login-request' | 'authorize' | 'done';
            originalUrl?: string; // GET /auth/authorize를 호출 할 때 original url + query
        };
    }
}

async function bootstrap() {
    const app = await NestFactory.create<NestExpressApplication>(AppModule);

    const redisClient = app.get<Redis>(REDIS_CLIENT);
    const configService = app.get<ConfigService>(ConfigService);

    app.useStaticAssets(join(__dirname, '..', 'public'));
    app.setBaseViewsDir(join(__dirname, 'views'));
    app.setViewEngine('hbs');

    app.use(
        session({
            store: new RedisStore({
                client: redisClient,
                prefix: 'oauth-session-',
                ttl: 60 * 60 * 1000,
            }),
            secret: configService.get('SESSION_SECRET'),
            resave: false,
            saveUninitialized: false,
            cookie: {
                httpOnly: true,
                secure: false,
                maxAge: 60 * 60 * 1000,
            },
        }),
    );

    app.use(passport.initialize());
    app.use(passport.session());

    app.useGlobalPipes(new ValidationPipe());
    app.useGlobalFilters(new HttpExceptionFilter());

    await app.listen(3000);
}
bootstrap();
