import { randomUUID } from 'crypto';
import { Database, MigrationRunner } from '@riao/dbal';
import { AuthMigrations } from '@riao/iam/auth/auth-migrations';
import {
	ApiRequest,
	AuthenticatedPrincipal,
	BaseApiEndpoint,
	BaseApiRouter,
	BearerAuthenticationScheme,
	RestServer,
} from 'api-machine';
import { maindb } from '../database/main';
import { AuthzRbacMigrations, RbacAuthorization } from '../src';

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
			swaggerEnabled: true,
			authorizer: new RbacAuthorization({ db }),
			authentication: new BearerAuthenticationScheme({ checkToken }),
		});
	}
}

async function runExample(): Promise<void> {
	const port = Number(process.env['RBAC_EXAMPLE_PORT'] ?? 3000);
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		throw new TypeError(
			'RBAC_EXAMPLE_PORT must be an integer from 1 to 65535'
		);
	}

	await maindb.init();
	try {
		const migrations = new MigrationRunner(maindb);
		await migrations.run({ auth: new AuthMigrations() });
		await migrations.run({ rbac: new AuthzRbacMigrations() });

		const principalId = randomUUID();
		const token = randomUUID();
		const principals = maindb.getQueryRepository({
			table: 'iam_principals',
			identifiedBy: 'id',
		});
		await principals.insertOne({
			record: {
				id: principalId,
				type: 'service',
				login: `rbac-example-${principalId}`,
				name: 'RBAC Example Service',
				create_timestamp: new Date(),
			},
		});

		const authorization = new RbacAuthorization({ db: maindb });
		await authorization.grantPermission({
			principalId,
			action: 'read',
			resource: 'documents',
		});

		const server = new RbacExampleServer(
			maindb,
			async (providedToken) => providedToken === token ?
				{ id: principalId } : false,
			port,
		);
		await server.start();

		const shutdown = async () => {
			await server.stop();
			await maindb.disconnect();
		};
		process.once('SIGINT', () => {
			shutdown().catch((error: unknown) => {
				/* eslint-disable-next-line no-console */
				console.error('Failed to stop the RBAC example:', error);
				process.exitCode = 1;
			});
		});
		process.once('SIGTERM', () => {
			shutdown().catch((error: unknown) => {
				/* eslint-disable-next-line no-console */
				console.error('Failed to stop the RBAC example:', error);
				process.exitCode = 1;
			});
		});

		/* eslint-disable-next-line no-console */
		console.log(`RBAC example listening on http://localhost:${port}/docs`);
		/* eslint-disable-next-line no-console */
		console.log(`Demo bearer token: ${token}`);
		/* eslint-disable-next-line no-console */
		console.log('Try GET /health and GET /documents with that token.');
	}
	catch (error) {
		await maindb.disconnect();
		throw error;
	}
}

if (require.main === module) {
	runExample().catch((error: unknown) => {
		/* eslint-disable-next-line no-console */
		console.error('Failed to start the RBAC example:', error);
		process.exitCode = 1;
	});
}