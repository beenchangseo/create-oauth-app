import { BadRequestException } from '@nestjs/common';

export type Detail = {
    field: string;
    issue: string;
};

export class InvalidArgumentException extends BadRequestException {
    errorCode: string;
    details: Detail[];

    constructor(details: Detail[]) {
        super();
        this.errorCode = 'INVALID_ARGUMENT_ERROR';
        this.message = '입력한 정보가 올바르지 않습니다.';
        this.details = details;
    }
}
