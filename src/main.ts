import { RequestMethod, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';
import { requestContextMiddleware } from './common/middleware/request-context.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const isProduction = configService.get<string>('NODE_ENV') === 'production';
  const frontendOrigin = configService.get<string>(
    'FRONTEND_URL',
    isProduction ? 'https://aurescore.okoyedavid.com' : 'http://localhost:3000',
  );

  app.enableCors({
    origin: frontendOrigin,
    credentials: true,
  });
  app.use(cookieParser());
  app.use(requestContextMiddleware);
  app.enableShutdownHooks();
  app.setGlobalPrefix('api', {
    exclude: [
      { path: '.well-known/openid-configuration', method: RequestMethod.GET },
    ],
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  await app.listen(configService.get<number>('PORT', 3001));
}
void bootstrap();
