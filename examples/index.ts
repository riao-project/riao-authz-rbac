import { randomUUID } from 'crypto';
import { Database, MigrationRunner } from '@riao/dbal';
import { Authentication, Principal } from '@riao/iam';
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
import {
	AuthzRbacMigrations,
	DefaultRbacAuthzRouter,
	RbacAuthorization,
} from '../src';

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
		return [
			DefaultRbacAuthzRouter,
			DocumentsEndpoint,
			PublicHealthEndpoint,
		];
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

class ExampleAuthentication extends Authentication<Principal> {
	override async authenticate(): Promise<Principal | null> {
		return null;
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

		const iam = new ExampleAuthentication({ db: maindb });
		const principalId = String(await iam.createPrincipal({
			type: 'service',
			login: `rbac-example-${randomUUID()}`,
			name: 'RBAC Example Service',
		}));
		const token = randomUUID();

		const authorization = new RbacAuthorization({ db: maindb });
		const documentReaderId = await authorization.role({
			name: 'document-reader',
		});
		const readDocumentsId = await authorization.permission({
			action: 'read', resource: 'documents',
		});
		await authorization.addPermissionToRole({
			roleId: documentReaderId, permissionId: readDocumentsId,
		});
		await authorization.assignRole({
			principalId, roleId: documentReaderId,
		});

		const rbacManagerId = await authorization.role({
			name: 'rbac-manager',
		});
		const manageRbacId = await authorization.permission({
			action: 'manage', resource: 'rbac',
		});
		await authorization.addPermissionToRole({
			roleId: rbacManagerId, permissionId: manageRbacId,
		});
		await authorization.assignRole({
			principalId, roleId: rbacManagerId,
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
		console.log(
			'Try GET /health, GET /documents, and GET /rbac/roles ' +
			'with that token.'
		);
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