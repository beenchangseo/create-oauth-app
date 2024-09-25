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
    @IsEmail({}, {message: '이메일 형식이 올바르지 않습니다.'})
    email: string;

    @IsString({message: '패스워드는 형식이 올바르지 않습니다.'})
    password: string;
}
