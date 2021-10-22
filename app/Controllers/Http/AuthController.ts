import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { schema, rules } from '@ioc:Adonis/Core/Validator'
import Hash from '@ioc:Adonis/Core/Hash'

import User from 'App/Models/User'
import PasswordResetEmail from 'App/Mailers/PasswordResetEmail'
import VerifyEmail from 'App/Mailers/VerifyEmail'
import { UserTypeEnum } from '../../../@types/User'

export default class AuthController {
  public async login({ auth, request, response }: HttpContextContract) {
    const { email, password, rememberMe } = request.all()

    try {
      const user = await User.query().where('email', email).firstOrFail()

      // verify password
      if (!(await Hash.verify(user.password, password))) {
        throw new Error('Invalid credentials')
      }

      // Generate token
      const token = await auth.use('api').generate(user, {
        expiresIn: rememberMe ? '90days' : '30days',
      })

      return response.json({
        success: true,
        data: { user },
        token: token.toJSON(),
      })
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
      const isLoggedIn = auth.use('api').isLoggedIn

      // get username and email from the auth user object
      const user = auth.user

      return response.json({ success: true, user, isLoggedIn })
    } catch (error) {
      return response.badRequest({
        success: false,
        message: 'User not logged in',
      })
    }
  }

  public async logout({ auth, response }: HttpContextContract) {
    /*
     * logout user
     */
    await auth.use('api').revoke()

    return response.json({
      success: true,
      message: 'User successfully logged out',
    })
  }

  /*
   * @params: request object with email for the account for password reset
   *
   * checks if email is valid
   * if valid, checks if email present in the db
   * sends email to the email with a password reset link
   *
   */
  public async sendPasswordResetEmail({
    request,
    response,
    logger,
  }: HttpContextContract) {
    /*
     * email validation schema
     * the schema checks if the request email is valid
     * and also checks if the email exists is the email column of table users
     */
    const emailValidationSchema = schema.create({
      email: schema.string({}, [
        rules.email(),
        rules.exists({
          table: 'users',
          column: 'email',
        }),
      ]),
    })

    /*
     * messages to be returned based on which rules
     * the validation fails for
     */
    const messages = {
      'email.email': 'Email is not valid',
      'email.exists': 'No user exists with that email',
    }

    try {
      // validate request
      const { email } = await request.validate({
        schema: emailValidationSchema,
        messages,
      })

      // send email with reset password link
      new PasswordResetEmail().setEmail(email).createSignedUrl().send()

      return response.json({
        success: true,
        message: 'Password reset email sent',
      })
    } catch (error) {
      logger.error(error.message)
      return response.badRequest(error.messages)
    }
  }

  /*
   * @params context object
   * @returns User, success boolean, message
   *
   * adds a new user if valid to the database
   *  - validates request to add new user
   *  - if user valid update model
   *  - send verification email to new user
   */
  public async register({
    request,
    response,
    auth,
    logger,
  }: HttpContextContract) {
    /*
     * create validation schema to check input against
     *
     */
    const newUserSchema = schema.create({
      username: schema.string({ trim: true }, [
        // username must be unique
        rules.unique({
          table: 'users',
          column: 'username',
        }),
        rules.minLength(4),
      ]),
      email: schema.string({ trim: true }, [
        // check if valid email and is unique
        rules.email(),
        rules.unique({
          table: 'users',
          column: 'email',
        }),
      ]),
      userType: schema.enum(Object.values(UserTypeEnum)),
      password: schema.string({}, [
        rules.confirmed('passwordConfirmed'),
        rules.minLength(8),
      ]),
    })

    /*
     * error messages to show when validation rules fail
     */
    const messages = {
      'required': 'The {{ field }} is required to register an account',
      'username.unique': 'Username already taken',
      'email.unique': 'An account with this email already exists',
      'email.email': 'Email is not valid',
      'userType': 'User type is required',
      'passwordConfirmed.confirmed': 'Passwords do not match',
    }

    try {
      // validate inputs
      const { username, email, userType, password } = await request.validate({
        schema: newUserSchema,
        messages,
      })

      logger.info(`Adding new user to db: ${username}`)
      const user = await User.create({
        username,
        userType,
        email,
        password,
        isEmailVerified: false,
      })

      logger.info(`Generating new token for user : ${user.username}`)
      /*
       * generate new token
       */
      const token = await auth.use('api').generate(user, {
        expiresIn: '30days',
      })

      logger.info('Sending email -> verify:email')
      /*
       * set username, email and then send verification email to user
       */
      await new VerifyEmail()
        .setUsername(user.username)
        .setEmail(user.email)
        .createSignedUrl()
        .send()

      return response.json({
        user,
        success: true,
        message: 'User registered',
        token: token.toJSON(),
      })
    } catch (error) {
      logger.error(error)
      return response.badRequest(error.messages)
    }
  }

  /*
   * @param ctx object
   * @returns object with key success of type boolean
   *
   * resets the password for the account with the email in the request form
   * if password reset successfull
   *  * sends email to user
   *  * renders the success page with a button to
   *    route to the signIn page
   */
  public async resetPassword({ request, response, logger }) {
    // create validator
    const passwordResetSchema = schema.create({
      email: schema.string({}, [
        rules.email(),
        rules.exists({
          table: 'users',
          column: 'email',
        }),
      ]),
      password: schema.string({}, [
        rules.confirmed('passwordConfirmed'),
        rules.minLength(8),
      ]),
    })

    // error messages
    const messages = {
      'required': 'The {{ field }} is required',
      'email.email': 'Not a valid email',
      'email.exists': 'This user does not exist',
      'password.minLength': 'Password should be at least 8 characters long',
      'passwordConfirmed.confirmed': 'Passwords do not match',
    }

    try {
      const { email, password } = await request.input.validate({
        schema: passwordResetSchema,
        messages,
      })

      logger.info(`Resetting password for email ${email}`)
      const user = await User.findOrFail(email)

      user.password = password
      await user.save()

      logger.info(`Password reset for email ${email}`)

      return response.json({
        success: true,
        data: { email },
        message: 'User registered but not verified.',
      })
    } catch (error) {
      return response.json({ error: true, message: error.message })
    }
  }

  /*
   * @params ctx object of type HttpContextContract
   * @returns message of type string, and a success boolean
   *
   * validates email provided by a user on register
   * if the signature is valid, updates the database row to have emailVerified set to true
   * ex: request = http:.../verify/test@test.com?signature=...
   *  returns { message: 'Email validated' }
   *
   */
  public async validateEmail({
    request,
    response,
    logger,
  }: HttpContextContract) {
    // check is signature valid
    if (!request.hasValidSignature()) {
      return response.json({
        success: false,
        message: 'Invalid verification url',
      })
    }
    // udate model
    // return success response
    try {
      // verify/:email
      const email = request.params().email

      const user = await User.findByOrFail('email', email)
      // update user email verification status
      user.isEmailVerified = true
      await user.save()

      // log email update
      logger.info(`User email:${email} verified`)

      return response.json({
        success: true,
        message: 'Email verified.',
      })
    } catch (error) {
      logger.error(error.message)
      return response.badRequest(error.message)
    }
  }
}
