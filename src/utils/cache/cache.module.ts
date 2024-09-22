import { Global, Module } from '@nestjs/common';
import { redisProviders } from './cache.providers';

@Global()
@Module({
    providers: [...redisProviders],
    exports: [...redisProviders],
})
export class CacheModule {}
