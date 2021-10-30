import { DateTime } from 'luxon'
import { BaseModel, column, BelongsTo, belongsTo } from '@ioc:Adonis/Lucid/Orm'

import Resteraunt from 'App/Models/Resteraunt'

export default class Food extends BaseModel {
  @column({ isPrimary: true })
  public id: string

  @column()
  public resterauntId: string

  @column()
  public name: string

  @column()
  public description: string

  @column()
  public price: number

  @column()
  public currency: string

  @column()
  public ingredients: string[]

  @column()
  public calories: string

  @column.dateTime({ autoCreate: true })
  public createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true })
  public updatedAt: DateTime

  @belongsTo(() => Resteraunt)
  public resteraunt: BelongsTo<typeof Resteraunt>
}
