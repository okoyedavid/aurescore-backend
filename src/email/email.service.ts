import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Resend } from 'resend';

interface SendEmailVerificationInput {
  to: string;
  code: string;
  idempotencyKey: string;
}

interface SendLoginVerificationInput {
  to: string;
  code: string;
  idempotencyKey: string;
}

interface SendEmailChangeInput {
  to: string;
  code: string;
  idempotencyKey: string;
}

interface SendPasswordResetInput {
  to: string;
  code: string;
  idempotencyKey: string;
}

@Injectable()
export class EmailService {
  private readonly resend: Resend;
  private readonly from: string;

  constructor(configService: ConfigService) {
    this.resend = new Resend(configService.getOrThrow<string>('RESEND_KEY'));
    this.from = configService.getOrThrow<string>('RESEND_FROM_EMAIL');
  }

  async sendEmailVerification(
    input: SendEmailVerificationInput,
  ): Promise<void> {
    const { error } = await this.resend.emails.send(
      {
        from: this.from,
        to: input.to,
        subject: 'Verify your Aurescore email',
        text: `Your Aurescore verification code is ${input.code}. It expires in 5 minutes.`,
        html: [
          '<p>Your Aurescore verification code is:</p>',
          `<p style="font-size: 32px; font-weight: 700; letter-spacing: 8px">${input.code}</p>`,
          '<p>This code expires in 5 minutes. If you did not request it, you can ignore this email.</p>',
        ].join(''),
      },
      { idempotencyKey: input.idempotencyKey },
    );

    if (error) {
      throw new ServiceUnavailableException(
        'Unable to send the verification email',
      );
    }
  }

  async sendLoginVerification(
    input: SendLoginVerificationInput,
  ): Promise<void> {
    const { error } = await this.resend.emails.send(
      {
        from: this.from,
        to: input.to,
        subject: 'Complete your Aurescore login',
        text: `Your Aurescore login code is ${input.code}. It expires in 5 minutes.`,
        html: [
          '<p>Your Aurescore login code is:</p>',
          `<p style="font-size: 32px; font-weight: 700; letter-spacing: 8px">${input.code}</p>`,
          '<p>This code expires in 5 minutes. If you did not try to sign in, change your password.</p>',
        ].join(''),
      },
      { idempotencyKey: input.idempotencyKey },
    );

    if (error) {
      throw new ServiceUnavailableException('Unable to send the login email');
    }
  }

  async sendEmailChangeVerification(
    input: SendEmailChangeInput,
  ): Promise<void> {
    const { error } = await this.resend.emails.send(
      {
        from: this.from,
        to: input.to,
        subject: 'Confirm your new Aurescore email',
        text: `Your Aurescore email-change code is ${input.code}. It expires in 5 minutes.`,
        html: [
          '<p>Your Aurescore email-change code is:</p>',
          `<p style="font-size: 32px; font-weight: 700; letter-spacing: 8px">${input.code}</p>`,
          '<p>This code expires in 5 minutes. If you did not request this change, secure your account.</p>',
        ].join(''),
      },
      { idempotencyKey: input.idempotencyKey },
    );
    if (error) {
      throw new ServiceUnavailableException(
        'Unable to send the email-change verification',
      );
    }
  }

  async sendEmailChangedNotice(to: string): Promise<void> {
    const { error } = await this.resend.emails.send({
      from: this.from,
      to,
      subject: 'Your Aurescore email was changed',
      text: 'The email address on your Aurescore account was changed. If this was not you, contact support immediately.',
      html: '<p>The email address on your Aurescore account was changed. If this was not you, contact support immediately.</p>',
    });
    if (error) {
      throw new ServiceUnavailableException(
        'Unable to send the email-change notice',
      );
    }
  }

  async sendPasswordResetCode(input: SendPasswordResetInput): Promise<void> {
    const { error } = await this.resend.emails.send(
      {
        from: this.from,
        to: input.to,
        subject: 'Reset your Aurescore password',
        text: `Your Aurescore password-reset code is ${input.code}. It expires in 5 minutes.`,
        html: [
          '<p>Your Aurescore password-reset code is:</p>',
          `<p style="font-size: 32px; font-weight: 700; letter-spacing: 8px">${input.code}</p>`,
          '<p>This code expires in 5 minutes. If you did not request it, you can ignore this email and review your sessions.</p>',
        ].join(''),
      },
      { idempotencyKey: input.idempotencyKey },
    );
    if (error) {
      throw new ServiceUnavailableException(
        'Unable to send the password-reset email',
      );
    }
  }

  async sendPasswordResetNotice(to: string): Promise<void> {
    const { error } = await this.resend.emails.send({
      from: this.from,
      to,
      subject: 'Your Aurescore password was reset',
      text: 'Your Aurescore password was reset and all existing sessions were signed out. If this was not you, contact support immediately.',
      html: '<p>Your Aurescore password was reset and all existing sessions were signed out. If this was not you, contact support immediately.</p>',
    });
    if (error) {
      throw new ServiceUnavailableException(
        'Unable to send the password-reset notice',
      );
    }
  }
}
