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
        this.message = 'The information you entered is incorrect.';
        this.details = details;
    }
}
