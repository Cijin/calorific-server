import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

import User from 'App/Models/User'

export default class AuthController {
  public async login({ auth, request, response }: HttpContextContract) {
    const { email, password, rememberMe } = request.all()

    try {
      // attempt login
      await auth.use('api').attempt(email, password, rememberMe)

      const { username } = await User.query()
        .where('email', email)
        .firstOrFail()
      return response.json({ success: true, data: { username } })
    } catch (error) {
      return response.badRequest({
        success: false,
        message: 'Please check email or password',
      })
    }
  }

  public async isLoggedIn({ auth, response }: HttpContextContract) {
    try {
      await auth.use('api').authenticate()

      // get username and email from the auth user object
      const user = auth.user

      return response.json({ success: true, user })
    } catch (error) {
      return response.badRequest({ success: false, message: 'Not logged in' })
    }
  }

  public async logout({ auth, response }: HttpContextContract) {
    /*
     * logout user
     */
    await auth.use('api').logout()

    return response.json({ message: 'User successfully logged out' })
  }
}
