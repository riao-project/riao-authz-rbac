import { Database } from '@riao/dbal';
import {
	ApiRequest,
	AuthenticatedPrincipal,
	BaseApiEndpoint,
	BaseApiRouter,
	BearerAuthenticationScheme,
	RestServer,
} from 'api-machine';
import { RbacAuthorization } from '../src';

export class DocumentsEndpoint extends BaseApiEndpoint {
	override path = '/documents';
	override authorization = { action: 'read', resource: 'documents' };

	async handle(request: ApiRequest) {
		return { principalId: request.principal?.id };
	}
}

export class PublicHealthEndpoint extends BaseApiEndpoint {
	override path = '/health';
	override authentication = null;
	override authorization = null;

	async handle() {
		return { healthy: true };
	}
}

class Router extends BaseApiRouter {
	async routes() {
		return [DocumentsEndpoint, PublicHealthEndpoint];
	}
}

export class RbacExampleServer extends RestServer {
	override router = Router;

	public constructor(
		db: Database,
		checkToken: (token: string) => Promise<false | AuthenticatedPrincipal>,
		port = 3000
	) {
		super({
			port,
			requireAuthentication: true,
			authorizer: new RbacAuthorization({ db }),
			authentication: new BearerAuthenticationScheme({ checkToken }),
		});
	}
}