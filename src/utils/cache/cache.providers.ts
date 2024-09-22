import { Provider } from '@nestjs/common';
import Redis from 'ioredis';
import { ConfigService } from '@nestjs/config';

export const REDIS_CLIENT = 'REDIS_CLIENT';

export const redisProviders: Provider[] = [
    {
        provide: REDIS_CLIENT,
        useFactory: async (configService: ConfigService) => {
            const redis = new Redis({
                host: configService.get<string>('REDIS_HOST'),
                port: configService.get<number>('REDIS_PORT'),
                password: configService.get<string>('REDIS_PASSWORD'),
                // db: configService.get<number>('REDIS_DB'),
            });

            redis.on('connect', () => {
                console.log('Redis client connected');
            });

            redis.on('error', (err) => {
                console.error('Redis client error', err);
            });

            return redis;
        },
        inject: [ConfigService],
    },
];
