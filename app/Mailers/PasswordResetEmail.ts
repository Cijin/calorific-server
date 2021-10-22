import Mail, { BaseMailer, MessageContract } from '@ioc:Adonis/Addons/Mail'
import Route from '@ioc:Adonis/Core/Route'
import ENV from '@ioc:Adonis/Core/Env'
import Logger from '@ioc:Adonis/Core/Logger'

export default class PasswordResetEmail extends BaseMailer {
  // use mailgun as the mailer
  public mailer = Mail.use('mailgun')
  /*
   * email to be verfied
   * signedURL to validate password reset url
   */
  protected email = ''
  protected signedURL = ''

  // set email
  public setEmail(email: string) {
    this.email = email
    return this
  }

  /*
   * takes no argument
   * uses the protected property email to create a new signed url
   * with the route '/resetPassword/:email' where email is the email to be  verfied
   * password reset url's expires in 30 minutes
   * uses domain from the env variable to give a complete url
   */
  public createSignedUrl() {
    // get domain
    const domain = ENV.get('DOMAIN')
    // build signedURL
    this.signedURL = Route.builder()
      .params({ email: this.email })
      .prefixUrl(domain)
      .makeSigned('/resetPassword/:email', { expiresIn: '30m' })

    return this
  }

  /**
   * The prepare method is invoked automatically when you run
   * "PasswordResetEmail.send".
   *
   * Use this method to prepare the email message. The method can
   * also be async.
   */
  public prepare(message: MessageContract) {
    const fromEmail = ENV.get('FROM_EMAIL')

    Logger.info(`Sending verification email to ${this.email}`)

    message
      .from(fromEmail)
      .to(this.email)
      .subject('Password reset request for devblabber account')
      // renders the file at public/emails/resetPassword.edge with the following params
      .htmlView('emails/resetPassword', { signedURL: this.signedURL })
  }
}
