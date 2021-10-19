import Mail, { BaseMailer, MessageContract } from '@ioc:Adonis/Addons/Mail'
import Route from '@ioc:Adonis/Core/Route'
import ENV from '@ioc:Adonis/Core/Env'
import Logger from '@ioc:Adonis/Core/Logger'

export default class VerifyEmail extends BaseMailer {
  /*
   * add username and email, as these are required to
   * verify email
   */
  protected username = ''
  protected email = ''
  protected signedURL = ''

  // use mailgun as the mailer
  public mailer = Mail.use('mailgun')

  // set username
  public setUsername(username: string) {
    this.username = username
    return this
  }

  // set email
  public setEmail(email: string) {
    this.email = email
    return this
  }

  /*
   * takes no argument
   * uses the protected property email to create a new signed url
   * with the route '/verify/:email' where email is the email to be  verfied
   * uses domain from the env variable to give a complete url
   */
  public createSignedUrl() {
    // get domain
    const domain = ENV.get('DOMAIN')
    this.signedURL = Route.builder()
      .params({ email: this.email })
      .prefixUrl(domain)
      .makeSigned('/verify/:email')

    return this
  }

  /**
   * The prepare method is invoked automatically when you run
   * "VerifyEmail.send".
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
      .subject('Verify email for devblabber')
      // renders the file at public/emails/verifyEmail.edge with the following params
      .htmlView('emails/verifyEmail', {
        username: this.username,
        signedURL: this.signedURL,
      })
  }
}
