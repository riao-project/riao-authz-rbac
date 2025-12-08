import { CreateTimestampColumn, UUIDKeyColumn } from '@riao/dbal/column-pack';
import { ColumnType, Migration } from '@riao/dbal';

export class CreateRolePermissionsTableMigration extends Migration {
	override async up(): Promise<void> {
		await this.ddl.createTable({
			name: 'iam_rbac_role_permissions',
			columns: [
				UUIDKeyColumn,
				{
					name: 'role_id',
					type: ColumnType.UUID,
					required: true,
					fk: {
						referencesTable: 'iam_rbac_roles',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				{
					name: 'permission_id',
					type: ColumnType.UUID,
					required: true,
					fk: {
						referencesTable: 'iam_rbac_permissions',
						referencesColumn: 'id',
						onDelete: 'CASCADE',
					},
				},
				CreateTimestampColumn,
			],
		});

		// TODO: Prevent duplicate role_id + permission_id entries?
	}

	override async down(): Promise<void> {
		await this.ddl.dropTable({
			tables: ['iam_rbac_role_permissions'],
		});
	}
}
