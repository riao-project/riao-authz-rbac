import { RiaoCreateEndpoint, DatabaseRecordWithId } from '@riao/rest';
import { ApiRequest, ApiResponse, ApiNextFunction } from 'api-machine';
import { RbacAuthorization } from '../../authz-rbac';

/**
 * POST /evaluate - Check if principal can perform action
 */
export class EvaluateAuthorizationEndpoint extends RiaoCreateEndpoint<any> {
	public override path = '/evaluate';
	public override description =
		'Evaluate if a principal can perform an action';

	protected auth: RbacAuthorization;

	public override bodyExample = {
		principalId: 'principal-123',
		action: 'read',
		resource: 'documents',
	};

	public override inject() {
		super.inject();
		this.auth = this.container.require<RbacAuthorization>('auth');
	}

	public override async handle(
		request: ApiRequest,
		response: ApiResponse,
		next: ApiNextFunction
	): Promise<any> {
		const principalId = request.body?.principalId as string;
		const action = request.body?.action as string;
		const resource = request.body?.resource as string;

		try {
			const result = await this.auth.evaluate?.({
				principal: { id: principalId } as any,
				action: action as string,
				resource: resource,
			});

			return result;
		}
		catch (error) {
			const message =
				error instanceof Error
					? error.message
					: 'Authorization evaluation failed';

			throw new Error(message);
		}
	}
}
