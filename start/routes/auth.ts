/*
|--------------------------------------------------------------------------
| Auth Routes
|--------------------------------------------------------------------------
|
|
*/
import Route from '@ioc:Adonis/Core/Route'

Route.group(() => {
  Route.post('login', 'AuthController.login')
  Route.get('isLoggedIn', 'AuthController.isLoggedIn')

  Route.get('logout', 'AuthController.logout')

  Route.post('/register', 'AuthController.register')
  /*
   * PasswordResetController
   * sendResetEmail -> sends email with signed reset link
   * resetPassword -> resets the password from the above link
   */
  Route.post('/forgotPassword', 'AuthController.sendPasswordResetEmail')
  Route.post('/resetPassword', 'AuthController.resetPassword')
  /*
  |--------------------------------------------------------------------------
  | Email Routes
  |--------------------------------------------------------------------------
  */
  // validate emails
  Route.get('/verify/:email', 'AuthController.validateEmail')
}).prefix('/api/')
