export const enum UserTypes {
  RESTAURANT = 'Restaurant',
  DINER = 'Diner',
}

export type UserType = UserTypes.RESTAURANT | UserTypes.DINER
