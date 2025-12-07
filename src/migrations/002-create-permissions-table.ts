import { CreateTimestampColumn, UUIDKeyColumn } from '@riao/dbal/column-pack';
import { ColumnType, Migration } from '@riao/dbal';

export class CreatePermissionsTableMigration extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'iam_rbac_permissions',
			columns: [
				UUIDKeyColumn,
				{
					name: 'action',
					type: ColumnType.VARCHAR,
					length: 100,
					required: true,
				},
				{
					name: 'resource',
					type: ColumnType.VARCHAR,
					length: 255,
				},
				{
					name: 'description',
					type: ColumnType.TEXT,
				},
				CreateTimestampColumn,
			],
		});

		// TODO: Prevent duplicate action + resource entries?
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({
			tables: ['iam_rbac_permissions'],
		});
	}
}
