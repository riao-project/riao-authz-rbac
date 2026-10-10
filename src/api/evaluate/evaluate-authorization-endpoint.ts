import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest } from 'api-machine';
import { UnauthorizedError } from 'api-machine';
import { Principal } from '@riao/iam/auth';
import { RbacAuthorization } from '../../authz-rbac';
import { RBAC_AUTHORIZATION_KEY } from '../authz-key';
import { AuthorizationResult } from 'api-machine';

/**
 * POST /evaluate - Check if principal can perform action
 */
// eslint-disable-next-line no-console
export class EvaluateAuthorizationEndpoint extends RiaoCreateEndpoint<
	DatabaseRecordWithId
> {
	public override path = '/evaluate';
	public override description =
		'Evaluate if a principal can perform an action';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		action: 'read',
		resource: 'documents',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>(
			RBAC_AUTHORIZATION_KEY
		);
	}

	public override async handle(
		request: ApiRequest
	): Promise<AuthorizationResult> {
		const principal = (
			request as ApiRequest & { principal?: Principal }
		).principal;
		if (!principal) {
			console.warn(
				'[AuthZ-API] Evaluate called without authenticated principal'
			);
			throw new UnauthorizedError(
				'An authenticated principal is required'
			);
		}

		const action = request.body?.action as string;
		const resource = request.body?.resource as string;

		if (!action) {
			console.warn(
				`[AuthZ-API] Evaluate request missing action for principal ${principal.id}`
			);
			throw new Error('Action is required for authorization evaluation');
		}

		try {
			const result = await this.auth.evaluate?.({
				principal,
				action: action as string,
				resource: resource,
			});

			if (!result) {
				console.error(
					`[AuthZ-API] Authorization evaluation returned no result for principal ${principal.id}`
				);
				throw new Error(
					'Authorization evaluation returned no result'
				);
			}

			console.log(
				`[AuthZ-API] Authorization evaluated for principal ${principal.id}:`,
				{
					action,
					resource,
					allowed: result.allowed,
				}
			);

			return result;
		} catch (error) {
			const message =
				error instanceof Error
					? error.message
					: 'Authorization evaluation failed';

			console.error(
				`[AuthZ-API] Authorization evaluation error for principal ${principal.id}:`,
				{ error: message }
			);

			throw new Error(message);
		}
	}
}
