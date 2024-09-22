import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';
import { Detail, InvalidArgumentException } from '../../errors/invalidArgumentException';
import { CustomUnauthorizedException } from '../../errors/unauthorizedException';

type HttpErrorResponse = {
    status: number;
    error: string;
    message: string;
    details?: Detail[];
};

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();
        const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

        // 기본 에러 응답 형식
        let errorResponse: HttpErrorResponse = {
            status: status,
            error: 'Internal Server Error',
            message: '일시적인 오류가 발생했습니다. 잠시 후 다시 시도해주세요.',
        };

        // HttpException인 경우 상세 정보 설정
        if (exception instanceof InvalidArgumentException) {
            errorResponse = {
                status: exception.getStatus(),
                error: exception.errorCode,
                message: exception.message,
                details: exception.details,
            };
        } else if (exception instanceof CustomUnauthorizedException) {
            errorResponse = {
                status: exception.getStatus(),
                error: exception.errorCode,
                message: exception.message,
            };
        } else {
            console.error({
                timestamp: new Date().toISOString(),
                path: request.url,
                errorResponse,
                exception,
            });
        }

        response.status(status).json(errorResponse);
    }
}
