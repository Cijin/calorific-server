import BaseSchema from '@ioc:Adonis/Lucid/Schema'

export default class Foods extends BaseSchema {
  protected tableName = 'foods'

  public async up() {
    this.schema.createTable(this.tableName, (table) => {
      table
        .uuid('id')
        .primary()
        .defaultTo(this.db.rawQuery('uuid_generate_v4()').knexQuery)

      table.uuid('resteraunt_id').references('resteraunts.id').notNullable()
      table.string('name').notNullable()
      table.text('description').notNullable()
      table.float('price').notNullable()
      table.string('currency').notNullable()
      table.specificType('ingredients', 'TEXT[]').notNullable()
      table.integer('calories').notNullable()

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
