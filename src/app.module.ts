import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaModule } from './prisma/prisma.module';
import { ConfigModule } from '@nestjs/config';
import { CacheModule } from './utils/cache/cache.module';
import { UserModule } from './user/user.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
        }),
        AuthModule,
        PrismaModule,
        CacheModule,
        UserModule,
    ],
})
export class AppModule {}
