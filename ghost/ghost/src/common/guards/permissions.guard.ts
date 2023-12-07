import {
    Injectable,
    CanActivate,
    ExecutionContext,
    Inject,
    UnauthorizedException
} from '@nestjs/common';
import {Reflector} from '@nestjs/core';
import {Roles} from '../decorators/permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
    constructor(@Inject(Reflector) private reflector: Reflector) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const roles = this.reflector.get(Roles, context.getHandler());
        if (!roles) {
            throw new UnauthorizedException('No roles defined');
        }

        const request = context.switchToHttp().getRequest();
        if (!request.user) {
            throw new UnauthorizedException('No user found');
        }

        await request.user.related('roles').fetch();

        const user = request.user.toJSON();

        const role = user?.roles?.[0]?.name;

        if (!role) {
            throw new UnauthorizedException('No role found');
        }

        if (roles.includes(role)) {
            return true;
        }
        return false;
    }
}
