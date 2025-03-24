import { Post, Get, RestController } from '@/decorators';
import { Response } from 'express';
import { AuthService } from '@/auth/auth.service';
import { UserRepository } from '@/databases/repositories/user.repository';
import { EventService } from '@/events/event.service';
import { AuthlessRequest } from '@/requests';
import { AuthError } from '@/errors/response-errors/auth.error';
import Redis from 'ioredis';
import config from '@/config';

interface ZPortalAutoLoginDto {
	email: string;
	token: string;
}

const redis = new Redis({
	host: 'redis',
	port: 6379, // notice: as a number
});

const MAGIC_TOKEN_PREFIX = 'magic_token:';

@RestController()
export class ZPortalAutoLoginController {
	constructor(
		private readonly authService: AuthService,
		private readonly userRepository: UserRepository,
		private readonly eventService: EventService,
	) {}

	@Post('/auto-login', { skipAuth: true })
	async autoLogin(req: AuthlessRequest, res: Response) {
		const { email, token } = req.body as ZPortalAutoLoginDto;

		const VALID_TOKEN =
			'E9iUdX5FfaDZi562QpIeWr2sC4wxdlUkGl02zFWojQgZLthhzBuXiv8dd8g7CNv30ZLJJflBmo6BpAMWPGF1a81DG0Frsgdvds5ni3fn5NB2BaIKFUHuQ1RQKw6PsAwZ';

		if (token !== VALID_TOKEN) {
			throw new AuthError('Invalid token');
		}

		const user = (await this.userRepository.findManyByEmail([email]))[0];

		if (!user) {
			throw new AuthError('User not found');
		}

		// Generate a short-lived token (valid for 5 min)
		const magicToken = crypto.randomUUID();
		await redis.set(`${MAGIC_TOKEN_PREFIX}${magicToken}`, user.id, 'EX', 300);

		const link = `${process.env.N8N_PROTOCOL}://${process.env.N8N_HOST}/rest/login-callback/${magicToken}`;

		return {
			success: true,
			magicLoginUrl: link,
		};
	}

	@Get('/login-callback/:token', { skipAuth: true })
	async loginCallback(req: AuthlessRequest, res: Response) {
		const { token } = req.params as { token: string };

		const userId = await redis.get(`${MAGIC_TOKEN_PREFIX}${token}`);
		if (!userId) {
			return res.status(401).send('Login link expired or invalid');
		}

		const user = await this.userRepository.findOneById(userId);
		if (!user) {
			throw new AuthError('User not found');
		}

		this.authService.issueCookie(res, user, req.browserId);
		this.eventService.emit('user-logged-in', {
			user,
			authenticationMethod: 'email',
		});

		// Optionally delete token after use
		await redis.del(`${MAGIC_TOKEN_PREFIX}${token}`);

		// Redirect to the dashboard or wherever
		return res.redirect('/');
	}
}
