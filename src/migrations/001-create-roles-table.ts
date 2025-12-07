import { CreateTimestampColumn, UUIDKeyColumn } from '@riao/dbal/column-pack';
import { ColumnType, Migration } from '@riao/dbal';

export class CreateRolesTableMigration extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'iam_rbac_roles',
			columns: [
				UUIDKeyColumn,
				{
					name: 'name',
					type: ColumnType.VARCHAR,
					length: 100,
					required: true,
					isUnique: true,
				},
				{
					name: 'description',
					type: ColumnType.TEXT,
				},
				CreateTimestampColumn,
				{
					name: 'deactivate_timestamp',
					type: ColumnType.TIMESTAMP,
				},
			],
		});
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({
			tables: ['iam_rbac_roles'],
		});
	}
}
