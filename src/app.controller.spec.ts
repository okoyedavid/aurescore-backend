import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { AppService } from './app.service';

describe('AppController', () => {
  let appController: AppController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
    }).compile();

    appController = app.get<AppController>(AppController);
  });

  describe('root', () => {
    it('should report that the backend is running', () => {
      expect(appController.getStatus()).toBe('Backend is running');
    });
  });

  describe('health', () => {
    it('should return an ok status', () => {
      expect(appController.getHealth()).toEqual({ status: 'ok' });
    });
  });
});
