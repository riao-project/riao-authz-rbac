import 'jasmine';
import { maindb } from '../../database/main';

beforeAll(async () => {
	const port = process.env['RIAO_TEST_POSTGRES_PORT'];
	if (port === undefined) {
		await maindb.init();
		return;
	}

	const parsedPort = Number(port);
	if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
		throw new Error('RIAO_TEST_POSTGRES_PORT must be a valid TCP port');
	}
	await maindb.init({
		connectionOptions: {
			host: '127.0.0.1',
			port: parsedPort,
			username: 'postgres',
			password: '',
			database: 'main',
		},
		useSchemaCache: false,
	});
});

afterAll(async () => {
	await maindb.disconnect();
});
