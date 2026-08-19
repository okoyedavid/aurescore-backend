import { Test, TestingModule } from '@nestjs/testing';
import { AccessTokenGuard } from '../auth-guard/access-token.guard';
import { LocationService } from '../location/location.service';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';

describe('UsersController', () => {
  let controller: UsersController;
  const users = {
    getCurrentUser: jest.fn(),
    updateProfile: jest.fn(),
    updatePreferences: jest.fn(),
    changePassword: jest.fn(),
    requestEmailChange: jest.fn(),
    confirmEmailChange: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        { provide: UsersService, useValue: users },
        {
          provide: LocationService,
          useValue: { getRequestContext: jest.fn() },
        },
      ],
    })
      .overrideGuard(AccessTokenGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<UsersController>(UsersController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
