import { DateTime } from 'luxon'
import { BaseModel, column } from '@ioc:Adonis/Lucid/Orm'

export default class Resteraunt extends BaseModel {
  /*
   * use uuid as primary key
   * self assign key every time a new resteraunt is created
   */
  public static selfAssignPrimaryKey = true

  @column({ isPrimary: true })
  public id: string

  @column()
  public lattitude: number

  @column()
  public longitude: number

  @column()
  public name: string

  @column()
  public address: string

  @column.dateTime({ autoCreate: true })
  public createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  public updatedAt: DateTime
}
