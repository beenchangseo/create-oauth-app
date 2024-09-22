import { IsEmail, IsString } from 'class-validator';

export class GetAuthorizeDto {
    @IsString()
    client_id: string;

    @IsString()
    redirect_uri: string;

    @IsString()
    scope: string;

    @IsString()
    state: string;

    @IsString()
    response_type: string;
}

export class PostAuthorizeDto {
    @IsString()
    client_id: string;

    @IsString()
    redirect_uri: string;

    @IsString()
    scope: string;

    @IsString()
    state: string;

    @IsString()
    response_type: string;

    @IsString()
    action: string;
}

export class LoginDto {
    @IsEmail()
    email: string;

    @IsString()
    password: string;
}
