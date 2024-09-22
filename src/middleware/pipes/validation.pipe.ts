import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import { ValidationError, validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { InvalidArgumentException } from '../../errors/invalidArgumentException';

@Injectable()
export class ValidationPipe implements PipeTransform<any> {
    async transform(value: any, { metatype }: ArgumentMetadata) {
        if (!metatype || !this.toValidate(metatype)) {
            return value;
        }
        const object = plainToInstance(metatype, value);
        const errors = await validate(object);
        if (errors.length > 0) {
            throw new InvalidArgumentException(this.formatErrors(errors));
        }
        return value;
    }

    private toValidate(metatype: Function): boolean {
        const types: Function[] = [String, Boolean, Number, Array, Object];
        return !types.includes(metatype);
    }

    private formatErrors(errors: ValidationError[]) {
        return errors.flatMap((error) => this.mapChildrenToValidationErrors(error));
    }

    private mapChildrenToValidationErrors(error: ValidationError, parentPath = ''): any[] {
        const field = parentPath ? `${parentPath}.${error.property}` : error.property;

        if (error.constraints) {
            return Object.values(error.constraints).map((issue) => ({
                field,
                issue,
            }));
        }

        if (error.children && error.children.length > 0) {
            return error.children.flatMap((childError) => this.mapChildrenToValidationErrors(childError, field));
        }

        return [];
    }
}
