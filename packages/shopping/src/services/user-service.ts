// Copyright IBM Corp. 2019. All Rights Reserved.
// Node module: @loopback/authentication
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

import {HttpErrors} from '@loopback/rest';
import {Credentials, UserRepository} from '../repositories/user.repository';
import {User} from '../models/user.model';
import {UserService, UserProfile} from '@loopback/authentication';
import {repository} from '@loopback/repository';
import {PasswordHasher} from './hash.password.bcryptjs';
import {PasswordHasherBindings} from '../keys';
import {inject} from '@loopback/context';
import * as isemail from 'isemail';

export class MyUserService implements UserService<User, Credentials> {
  constructor(
    @repository(UserRepository) public userRepository: UserRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public passwordHasher: PasswordHasher,
  ) {}

  async verifyCredentials(credentials: Credentials): Promise<User> {
    const foundUser = await this.userRepository.findOne({
      where: {email: credentials.email},
    });

    if (!foundUser) {
      throw new HttpErrors.NotFound(
        `User with email ${credentials.email} not found.`,
      );
    }

    const passwordMatched = await this.passwordHasher.comparePassword(
      credentials.password,
      foundUser.password,
    );

    if (!passwordMatched) {
      throw new HttpErrors.Unauthorized('The credentials are not correct.');
    }

    return foundUser;
  }

  convertToUserProfile(user: User): UserProfile {
    // since first name and surname are optional, no error is thrown if not provided
    let userName = '';
    if (user.firstname && user.surname) {
      userName = `${user.firstname} ${user.surname}`;
    }

    return {id: user.id, name: userName};
  }

  async validateCredentials(credentials: Credentials) {
    // Validate Email
    if (!isemail.validate(credentials.email)) {
      throw new HttpErrors.UnprocessableEntity('invalid email');
    }

    // Validate Password Length
    if (credentials.password.length < 8) {
      throw new HttpErrors.UnprocessableEntity(
        'password must be minimum 8 characters',
      );
    }
  }
}
