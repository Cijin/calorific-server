import BaseSchema from '@ioc:Adonis/Lucid/Schema'

export default class Resteraunts extends BaseSchema {
  protected tableName = 'resteraunts'

  public async up() {
    this.schema.createTable(this.tableName, (table) => {
      table
        .uuid('id')
        .primary()
        .defaultTo(this.db.rawQuery('uuid_generate_v4()').knexQuery)

      table.float('longitude').notNullable()
      table.float('lattitude').notNullable()
      table.string('name').notNullable()
      table.text('address').notNullable()

      /**
       * Uses timestamptz for PostgreSQL and DATETIME2 for MSSQL
       */
      table.timestamp('created_at', { useTz: true })
      table.timestamp('updated_at', { useTz: true })
    })
  }

  public async down() {
    this.schema.dropTable(this.tableName)
  }
}
