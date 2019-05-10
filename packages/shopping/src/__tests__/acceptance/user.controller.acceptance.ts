// Copyright IBM Corp. 2018,2019. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {Client, expect /*, toJSON*/} from '@loopback/testlab';
import {ShoppingApplication} from '../..';
import {UserRepository, OrderRepository} from '../../repositories';
import {MongoDataSource} from '../../datasources';
import {setupApplication} from './helper';
import {
  createRecommendationServer,
  HttpServer,
} from 'loopback4-example-recommender';
const recommendations = require('loopback4-example-recommender/data/recommendations.json');

describe('UserController', () => {
  let app: ShoppingApplication;
  let client: Client;
  const mongodbDS = new MongoDataSource();
  const orderRepo = new OrderRepository(mongodbDS);
  const userRepo = new UserRepository(mongodbDS, orderRepo);

  const user = {
    id: '1',
    email: 'test@loopback.io',
    password: 'p4ssw0rd',
    firstname: 'Example',
    surname: 'User',
  };

  before('setupApplication', async () => {
    ({app, client} = await setupApplication());
  });

  beforeEach(clearDatabase);
  after(async () => {
    await app.stop();
  });

  it('creates new user when POST /users is invoked', async () => {
    const res = await client
      .post('/users')
      .send(user)
      .expect(200);

    // Assertions
    expect(res.body.email).to.equal('test@loopback.io');
    expect(res.body.firstname).to.equal('Example');
    expect(res.body.surname).to.equal('User');
    expect(res.body).to.have.property('id');
    expect(res.body).to.not.have.property('password');
  });

  it('throws error for POST /users with a missing email', async () => {
    const res = await client
      .post('/users')
      .send({
        id: '1',
        password: 'p4ssw0rd',
        firstname: 'Example',
        surname: 'User',
      })
      .expect(422);

    const errorText = JSON.parse(res.error.text);
    expect(errorText.error.details[0].info.missingProperty).to.equal('email');
  });

  it('throws error for POST /users with an invalid email', async () => {
    const res = await client
      .post('/users')
      .send({
        id: '1',
        email: 'test@loop&back.io',
        password: 'p4ssw0rd',
        firstname: 'Example',
        surname: 'User',
      })
      .expect(422);

    expect(res.body.error.message).to.equal('invalid email');
  });

  it('throws error for POST /users with a missing password', async () => {
    const res = await client
      .post('/users')
      .send({
        id: '1',
        email: 'test@loopback.io',
        firstname: 'Example',
        surname: 'User',
      })
      .expect(422);

    const errorText = JSON.parse(res.error.text);
    expect(errorText.error.details[0].info.missingProperty).to.equal(
      'password',
    );
  });

  it('throws error for POST /users with a string', async () => {
    const res = await client
      .post('/users')
      .send('hello')
      .expect(415);
    expect(res.body.error.message).to.equal(
      'Content-type application/x-www-form-urlencoded does not match [application/json].',
    );
  });

  it('returns a user with given id when GET /users/{id} is invoked', async () => {
    const newUser = await userRepo.create(user);
    delete newUser.password;
    delete newUser.orders;

    await client.get(`/users/${newUser.id}`).expect(200, newUser.toJSON());
  });

  describe('authentication', () => {
    it('login returns a valid token', async () => {
      await client
        .post('/users')
        .send(user)
        .expect(200);

      const res = await client
        .post('/users/login')
        .send({email: user.email, password: user.password})
        .expect(200);

      const token = res.body.token;
      expect(token).to.not.be.Null();
      expect(token).to.be.String();
      expect(token).to.not.be.empty();
      const parts = token.split('.');
      //token has 3 parts separated by '.'
      expect(parts.length).to.equal(3);
    });

    it('login returns an error when invalid email is used', async () => {
      await client
        .post('/users')
        .send(user)
        .expect(200);

      const res = await client
        .post('/users/login')
        .send({email: 'idontexist@example.com', password: user.password})
        .expect(404);

      expect(res.body.error.message).to.equal(
        'User with email idontexist@example.com not found.',
      );
    });

    it('login returns an error when invalid password is used', async () => {
      await client
        .post('/users')
        .send(user)
        .expect(200);

      const res = await client
        .post('/users/login')
        .send({email: user.email, password: 'wrongpassword'})
        .expect(401);

      expect(res.body.error.message).to.equal(
        'The credentials are not correct.',
      );
    });

    it('users/me returns the current user profile when a valid token is provided', async () => {
      await client
        .post('/users')
        .send(user)
        .expect(200);

      let res = await client
        .post('/users/login')
        .send({email: user.email, password: user.password})
        .expect(200);

      const token = res.body.token;

      res = await client
        .get('/users/me')
        .set('Authorization', 'Bearer ' + token)
        .expect(200);

      const userProfile = res.body;
      expect(userProfile.id).to.equal(user.id);
      expect(userProfile.name).to.equal(`${user.firstname} ${user.surname}`);
    });

    it('users/me returns an error when a token is not provided', async () => {
      const res = await client.get('/users/me').expect(401);

      expect(res.body.error.message).to.equal(
        'Authorization header not found.',
      );
    });

    it('users/me returns an error when an invalid token is provided', async () => {
      const res = await client
        .get('/users/me')
        .set('Authorization', 'Bearer ' + 'xxx.yyy.zzz')
        .expect(401);

      expect(res.body.error.message).to.equal(
        'Error verifying token : invalid token',
      );
    });

    it(`users/me returns an error when 'Bearer ' is not found in Authorization header`, async () => {
      const res = await client
        .get('/users/me')
        .set('Authorization', 'NotB3@r3r ' + 'xxx.yyy.zzz')
        .expect(401);

      expect(res.body.error.message).to.equal(
        "Authorization header is not of type 'Bearer'.",
      );
    });

    it('users/me returns an error when an expired token is provided', async () => {
      const expiredToken =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEiLCJuYW1lIjoiRXhhbXBsZSBVc2VyIiwiaWF0IjoxNTU3NTE1MTg1LCJleHAiOjE1NTc1MTUyNDV9.NZ31amMztvIYBth3SRY9fxiZTukObpgV2gSmJZ10pwY';
      const res = await client
        .get('/users/me')
        .set('Authorization', 'Bearer ' + expiredToken)
        .expect(401);

      expect(res.body.error.message).to.equal(
        'Error verifying token : jwt expired',
      );
    });
  });

  describe('user product recommendation (service) api', () => {
    // tslint:disable-next-line:no-any
    let recommendationService: HttpServer;

    before(async () => {
      recommendationService = createRecommendationServer();
      await recommendationService.start();
    });

    after(async () => {
      await recommendationService.stop();
    });

    it('returns product recommendations for a user', async () => {
      const newUser = await userRepo.create(user);
      await client
        .get(`/users/${newUser.id}/recommend`)
        .expect(200, recommendations);
    });
  });

  async function clearDatabase() {
    await userRepo.deleteAll();
  }
});
