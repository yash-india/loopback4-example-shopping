// Copyright IBM Corp. 2018,2019. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {repository} from '@loopback/repository';
import {post, param, get, requestBody} from '@loopback/rest';
import {User, Product} from '../models';
import {UserRepository} from '../repositories';
import {RecommenderService} from '../services/recommender.service';
import {inject, Setter} from '@loopback/core';
import {
  authenticate,
  UserProfile,
  AuthenticationBindings,
} from '@loopback/authentication';
import {
  CredentialsRequestBody,
  UserProfileSchema,
} from './specs/user-controller.specs';
import {Credentials} from '../repositories/user.repository';
import {PasswordHasher} from '../services/hash.password.bcryptjs';
import {JWTService} from '../services/jwt-service';
import {
  JWTAuthenticationStrategyBindings,
  PasswordHasherBindings,
  UserServiceBindings,
} from '../keys';
//import {validateCredentials} from '../services/JWT.authentication.service';
import * as _ from 'lodash';
import {MyUserService} from '../services/user-service';

export class UserController {
  constructor(
    @repository(UserRepository) public userRepository: UserRepository,
    @inject('services.RecommenderService')
    public recommender: RecommenderService,
    @inject.setter(AuthenticationBindings.CURRENT_USER)
    public setCurrentUser: Setter<UserProfile>,
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public passwordHasher: PasswordHasher,
    @inject(JWTAuthenticationStrategyBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
  ) {}

  @post('/users')
  async create(@requestBody() user: User): Promise<User> {
    // ensure a valid email value and password value
    await this.userService.validateCredentials(
      _.pick(user, ['email', 'password']),
    );

    // encrypt the password
    user.password = await this.passwordHasher.hashPassword(user.password);

    // create the new user
    const savedUser = await this.userRepository.create(user);
    delete savedUser.password;

    return savedUser;
  }

  @get('/users/{userId}', {
    responses: {
      '200': {
        description: 'User',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': User,
            },
          },
        },
      },
    },
  })
  async findById(@param.path.string('userId') userId: string): Promise<User> {
    return this.userRepository.findById(userId, {
      fields: {password: false},
    });
  }

  @get('/users/me', {
    responses: {
      '200': {
        description: 'The current user profile',
        content: {
          'application/json': {
            schema: UserProfileSchema,
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async printCurrentUser(
    @inject('authentication.currentUser') currentUserProfile: UserProfile,
  ): Promise<UserProfile> {
    return currentUserProfile;
  }

  @get('/users/{userId}/recommend', {
    responses: {
      '200': {
        description: 'Products',
        content: {
          'application/json': {
            schema: {
              type: 'array',
              items: {
                'x-ts-type': Product,
              },
            },
          },
        },
      },
    },
  })
  async productRecommendations(
    @param.path.string('userId') userId: string,
  ): Promise<Product[]> {
    return this.recommender.getProductRecommendations(userId);
  }

  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<{token: string}> {
    // ensure the user exists, and the password is correct
    const user = await this.userService.verifyCredentials(credentials);

    // convert a User object into a UserProfile object (reduced set of properties)
    const userProfile = this.userService.convertToUserProfile(user);

    // create a JSON Web Token based on the user profile
    const token = await this.jwtService.generateToken(userProfile);

    return {token};
  }
}
