import { UnauthorizedException } from '@nestjs/common';

export class CustomUnauthorizedException extends UnauthorizedException {
    errorCode: string;
    serverMessage?: string;

    constructor(message?: string, serverMessage?: string) {
        super();
        this.errorCode = 'UnauthorizedException';
        this.message = message ? message : 'Unauthorized';
        this.serverMessage = serverMessage ? serverMessage : undefined;
    }
}
