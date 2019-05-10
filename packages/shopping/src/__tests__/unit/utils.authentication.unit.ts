// Copyright IBM Corp. 2019. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {expect} from '@loopback/testlab';
import {MongoDataSource} from '../../datasources';
import {JWTService} from '../../services/jwt-service';
import {ShoppingApplication} from '../..';
import {PasswordHasher} from '../../services/hash.password.bcryptjs';
import {UserRepository, OrderRepository} from '../../repositories';
import {User} from '../../models';
import {HttpErrors} from '@loopback/rest';
import {
  PasswordHasherBindings,
  UserServiceBindings,
  JWTAuthenticationStrategyBindings,
} from '../../keys';
import {setupApplication} from './helper';
import {MyUserService} from '../../services/user-service';

describe('authentication services', () => {
  let app: ShoppingApplication;

  const mongodbDS = new MongoDataSource();
  const orderRepo = new OrderRepository(mongodbDS);
  const userRepo = new UserRepository(mongodbDS, orderRepo);

  const user = {
    id: '1',
    email: 'unittest@loopback.io',
    password: 'p4ssw0rd',
    firstname: 'unit',
    surname: 'test',
  };

  let newUser: User;
  let jwtService: JWTService;
  let userService: MyUserService;
  let bcryptHasher: PasswordHasher;

  before(setupApp);
  before(clearDatabase);
  before(createUser);
  before(createTokenService);
  before(createUserService);

  it('user service validateCredentials() succeeds', async () => {
    const credentials = {email: 'dom@example.com', password: 'p4ssw0rd'};
    return expect(
      userService.validateCredentials(credentials),
    ).to.be.fulfilled();
  });

  it('user service validateCredentials() fails with invalid email', async () => {
    const expectedError = new HttpErrors.UnprocessableEntity('invalid email');
    const credentials = {email: 'domdomdom', password: 'p4ssw0rd'};
    return expect(
      userService.validateCredentials(credentials),
    ).to.be.rejectedWith(expectedError);
  });

  it('user service validateCredentials() fails with invalid password', async () => {
    const expectedError = new HttpErrors.UnprocessableEntity(
      'password must be minimum 8 characters',
    );
    const credentials = {email: 'dom@example.com', password: 'p4ss'};
    return expect(
      userService.validateCredentials(credentials),
    ).to.be.rejectedWith(expectedError);
  });

  it('user service verifyCredentials() succeeds', async () => {
    const {email} = newUser;
    const credentials = {email, password: user.password};

    const returnedUser = await userService.verifyCredentials(credentials);

    // create a copy of returned user without password field
    const returnedUserWithOutPassword = Object.assign({}, returnedUser, {
      password: user.password,
    });
    delete returnedUserWithOutPassword.password;

    // create a copy of expected user without password field
    const expectedUserWithoutPassword = Object.assign({}, user);
    delete expectedUserWithoutPassword.password;

    expect(returnedUserWithOutPassword).to.deepEqual(
      expectedUserWithoutPassword,
    );
  });

  it('user service verifyCredentials() fails with user not found', async () => {
    const credentials = {email: 'idontexist@example.com', password: 'p4ssw0rd'};

    const expectedError = new HttpErrors.NotFound(
      `User with email ${credentials.email} not found.`,
    );

    await expect(userService.verifyCredentials(credentials)).to.be.rejectedWith(
      expectedError,
    );
  });

  it('user service verifyCredentials() fails with incorrect credentials', async () => {
    const {email} = newUser;
    const credentials = {email, password: 'invalidp4ssw0rd'};
    const expectedError = new HttpErrors.Unauthorized(
      'The credentials are not correct.',
    );

    await expect(userService.verifyCredentials(credentials)).to.be.rejectedWith(
      expectedError,
    );
  });

  it('user service convertToUserProfile() succeeds', async () => {
    const expectedUserProfile = {
      id: user.id,
      name: `${user.firstname} ${user.surname}`,
    };
    const userProfile = userService.convertToUserProfile(newUser);
    expect(expectedUserProfile).to.deepEqual(userProfile);
  });

  it('user service convertToUserProfile() succeeds without optional fields : firstname, surname', async () => {
    const userWithoutFirstOrSurname = Object.assign({}, newUser);
    delete userWithoutFirstOrSurname.firstname;
    delete userWithoutFirstOrSurname.surname;

    const userProfile = userService.convertToUserProfile(
      userWithoutFirstOrSurname,
    );
    expect(userProfile.id).to.equal(user.id);
    expect(userProfile.name).to.equal('');
  });

  it('token service generateToken() succeeds', async () => {
    const userProfile = userService.convertToUserProfile(newUser);
    const token = await jwtService.generateToken(userProfile);
    expect(token).not.Null();
    expect(token).to.be.String();
    const parts = token.split('.');
    //token has 3 parts separated by '.'
    expect(parts.length).to.equal(3);
  });

  it('token service verifyToken() succeeds', async () => {
    const userProfile = userService.convertToUserProfile(newUser);
    const token = await jwtService.generateToken(userProfile);
    const userProfileFromToken = await jwtService.verifyToken(token);

    expect(userProfileFromToken).to.deepEqual(userProfile);
  });

  it('token service verifyToken() fails', async () => {
    const expectedError = new HttpErrors.Unauthorized(
      `Error verifying token : invalid token`,
    );
    const invalidToken = 'aaa.bbb.ccc';
    await expect(jwtService.verifyToken(invalidToken)).to.be.rejectedWith(
      expectedError,
    );
  });

  it('password encrypter hashPassword() succeeds', async () => {
    const encrypedPassword = await bcryptHasher.hashPassword(user.password);
    expect(encrypedPassword).to.not.be.Null();
    expect(encrypedPassword).to.be.String();
    expect(encrypedPassword).to.not.equal(user.password);
  });

  it('password encrypter compare() succeeds', async () => {
    const encrypedPassword = await bcryptHasher.hashPassword(user.password);
    const passwordsAreTheSame = await bcryptHasher.comparePassword(
      user.password,
      encrypedPassword,
    );
    expect(passwordsAreTheSame).to.be.True();
  });

  it('password encrypter compare() fails', async () => {
    const encrypedPassword = await bcryptHasher.hashPassword(user.password);
    const passwordsAreTheSame = await bcryptHasher.comparePassword(
      'someotherpassword',
      encrypedPassword,
    );
    expect(passwordsAreTheSame).to.be.False();
  });

  async function setupApp() {
    app = await setupApplication();
    app.bind(PasswordHasherBindings.ROUNDS).to(4);
  }

  async function createUser() {
    bcryptHasher = await app.get(PasswordHasherBindings.PASSWORD_HASHER);
    const encryptedPassword = await bcryptHasher.hashPassword(user.password);
    newUser = await userRepo.create(
      Object.assign({}, user, {password: encryptedPassword}),
    );
  }

  async function clearDatabase() {
    await userRepo.deleteAll();
  }

  async function createTokenService() {
    jwtService = await app.get(JWTAuthenticationStrategyBindings.TOKEN_SERVICE);
  }

  async function createUserService() {
    userService = await app.get(UserServiceBindings.USER_SERVICE);
  }
});
