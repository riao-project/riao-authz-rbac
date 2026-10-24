import { Database, DatabaseRecord, QueryRepository } from '@riao/dbal';
import { RbacExampleServer } from '../../examples';

describe('RBAC server example contract', () => {
	let server: RbacExampleServer;
	let url: string;
	let repo: jasmine.SpyObj<QueryRepository<DatabaseRecord>>;

	class Server extends RbacExampleServer {
		get url(): string {
			const address = this.listener.address();
			if (!address || typeof address === 'string') {
				throw new Error('Expected TCP listener');
			}
			return `http://127.0.0.1:${address.port}`;
		}
	}

	beforeEach(async () => {
		const db = jasmine.createSpyObj<Database>('db', ['getQueryRepository']);
		repo = jasmine.createSpyObj<QueryRepository<DatabaseRecord>>(
			'repo', ['find']
		);
		repo.find.and.resolveTo([]);
		db.getQueryRepository.and.returnValue(repo);
		const instance = new Server(db, {
			verifyAccessToken: async (token) => token === 'valid'
				? { principal_id: 'trusted-user' } : null,
			findActivePrincipal: async ({ where }) => where.id
				? { id: where.id } : null,
		}, 0);
		server = instance;
		await server.start();
		url = instance.url;
	});

	afterEach(async () => {
		await server.stop();
	});

	it('leaves health explicitly public', async () => {
		expect((await fetch(`${url}/health`)).status).toBe(200);
		expect(repo.find).not.toHaveBeenCalled();
	});

	it('requires authentication before role lookup', async () => {
		expect((await fetch(`${url}/documents`)).status).toBe(401);
		expect(repo.find).not.toHaveBeenCalled();
	});

	it('evaluates roles for the trusted ID-only principal', async () => {
		const response = await fetch(`${url}/documents`, {
			headers: { Authorization: 'Bearer valid' },
		});
		expect(response.status).toBe(403);
		expect(repo.find).toHaveBeenCalledTimes(1);
		const query: { where?: unknown } = repo.find.calls.mostRecent().args[0];
		expect(query.where).toEqual({
			principal_id: 'trusted-user', deactivate_timestamp: null,
		});
	});
});
