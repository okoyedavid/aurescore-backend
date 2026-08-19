-- CreateEnum
CREATE TYPE "AuditCategory" AS ENUM ('authentication', 'account', 'session', 'security', 'business');

-- CreateEnum
CREATE TYPE "AuditOutcome" AS ENUM ('success', 'failure', 'blocked');

-- CreateEnum
CREATE TYPE "AuditSeverity" AS ENUM ('info', 'warning', 'error', 'critical');

-- CreateEnum
CREATE TYPE "AuthProviderType" AS ENUM ('GOOGLE', 'GITHUB', 'AUREX', 'AURESCORE', 'ANIMEX');

-- CreateEnum
CREATE TYPE "Status" AS ENUM ('active', 'suspended', 'pending_delete', 'banned');

-- CreateTable
CREATE TABLE "ApplicationError" (
    "errorId" TEXT NOT NULL,
    "requestId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "code" TEXT,
    "stack" TEXT,
    "statusCode" INTEGER NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "userId" TEXT,
    "userSessionId" TEXT,
    "authSessionId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "deviceName" TEXT,
    "environment" TEXT NOT NULL,
    "release" TEXT,
    "resolvedAt" TIMESTAMPTZ(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ApplicationError_pkey" PRIMARY KEY ("errorId")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "eventId" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "category" "AuditCategory" NOT NULL,
    "outcome" "AuditOutcome" NOT NULL,
    "severity" "AuditSeverity" NOT NULL DEFAULT 'info',
    "userId" TEXT,
    "emailHash" TEXT,
    "userSessionId" TEXT,
    "authSessionId" TEXT,
    "requestId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "deviceName" TEXT,
    "city" TEXT,
    "region" TEXT,
    "country" TEXT,
    "reason" TEXT,
    "changes" JSONB,
    "metadata" JSONB,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("eventId")
);

-- CreateTable
CREATE TABLE "AuthProvider" (
    "authProviderId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "provider" "AuthProviderType" NOT NULL,
    "providerUserId" TEXT NOT NULL,
    "providerEmail" TEXT,
    "linkedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthProvider_pkey" PRIMARY KEY ("authProviderId")
);

-- CreateTable
CREATE TABLE "AuthSession" (
    "authSessionId" TEXT NOT NULL,
    "userSessionId" TEXT NOT NULL,
    "refreshTokenHash" TEXT NOT NULL,
    "replacedByAuthSessionId" TEXT,
    "lastSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMPTZ(3) NOT NULL,
    "revokedAt" TIMESTAMPTZ(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthSession_pkey" PRIMARY KEY ("authSessionId")
);

-- CreateTable
CREATE TABLE "OAuthClient" (
    "clientId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "clientSecretHash" TEXT NOT NULL,
    "redirectUris" TEXT[],
    "allowedScopes" TEXT[],
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "OAuthClient_pkey" PRIMARY KEY ("clientId")
);

-- CreateTable
CREATE TABLE "OAuthGrant" (
    "grantId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "scopes" TEXT[],
    "grantedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" TIMESTAMPTZ(3),
    "revokedAt" TIMESTAMPTZ(3),

    CONSTRAINT "OAuthGrant_pkey" PRIMARY KEY ("grantId")
);

-- CreateTable
CREATE TABLE "UserSession" (
    "userSessionId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "currentAuthSessionId" TEXT NOT NULL,
    "userAgent" TEXT,
    "deviceName" TEXT,
    "ipAddress" TEXT,
    "city" TEXT,
    "region" TEXT,
    "country" TEXT,
    "lastSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMPTZ(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserSession_pkey" PRIMARY KEY ("userSessionId")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" VARCHAR(40) NOT NULL,
    "avatar" TEXT,
    "bio" TEXT,
    "username" TEXT,
    "emailVerifiedAt" TIMESTAMPTZ(3),
    "status" "Status" NOT NULL DEFAULT 'active',
    "passwordHash" TEXT,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserPreference" (
    "userId" TEXT NOT NULL,
    "desktopNotifications" BOOLEAN NOT NULL DEFAULT true,
    "telegramNotifications" BOOLEAN NOT NULL DEFAULT false,
    "whatsappNotifications" BOOLEAN NOT NULL DEFAULT false,
    "twoFactorEnabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "UserPreference_pkey" PRIMARY KEY ("userId")
);

-- CreateIndex
CREATE INDEX "ApplicationError_requestId_idx" ON "ApplicationError"("requestId");

-- CreateIndex
CREATE INDEX "ApplicationError_userId_idx" ON "ApplicationError"("userId");

-- CreateIndex
CREATE INDEX "ApplicationError_userSessionId_idx" ON "ApplicationError"("userSessionId");

-- CreateIndex
CREATE INDEX "ApplicationError_ipAddress_idx" ON "ApplicationError"("ipAddress");

-- CreateIndex
CREATE INDEX "ApplicationError_environment_createdAt_idx" ON "ApplicationError"("environment", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "ApplicationError_statusCode_createdAt_idx" ON "ApplicationError"("statusCode", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "ApplicationError_path_createdAt_idx" ON "ApplicationError"("path", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "AuditEvent_userId_createdAt_idx" ON "AuditEvent"("userId", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "AuditEvent_eventType_createdAt_idx" ON "AuditEvent"("eventType", "createdAt" DESC);

-- CreateIndex
CREATE INDEX "AuditEvent_requestId_idx" ON "AuditEvent"("requestId");

-- CreateIndex
CREATE INDEX "AuditEvent_userSessionId_idx" ON "AuditEvent"("userSessionId");

-- CreateIndex
CREATE INDEX "AuditEvent_createdAt_idx" ON "AuditEvent"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuthProvider_provider_providerUserId_key" ON "AuthProvider"("provider", "providerUserId");

-- CreateIndex
CREATE UNIQUE INDEX "AuthProvider_userId_provider_key" ON "AuthProvider"("userId", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "AuthSession_refreshTokenHash_key" ON "AuthSession"("refreshTokenHash");

-- CreateIndex
CREATE INDEX "AuthSession_userSessionId_idx" ON "AuthSession"("userSessionId");

-- CreateIndex
CREATE INDEX "AuthSession_expiresAt_idx" ON "AuthSession"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_slug_key" ON "OAuthClient"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthGrant_userId_clientId_key" ON "OAuthGrant"("userId", "clientId");

-- CreateIndex
CREATE UNIQUE INDEX "UserSession_currentAuthSessionId_key" ON "UserSession"("currentAuthSessionId");

-- CreateIndex
CREATE INDEX "UserSession_revokedAt_idx" ON "UserSession"("revokedAt");

-- CreateIndex
CREATE INDEX "UserSession_userId_idx" ON "UserSession"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- AddForeignKey
ALTER TABLE "AuthProvider" ADD CONSTRAINT "AuthProvider_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthSession" ADD CONSTRAINT "AuthSession_userSessionId_fkey" FOREIGN KEY ("userSessionId") REFERENCES "UserSession"("userSessionId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuthGrant" ADD CONSTRAINT "OAuthGrant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuthGrant" ADD CONSTRAINT "OAuthGrant_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "OAuthClient"("clientId") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserSession" ADD CONSTRAINT "UserSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserPreference" ADD CONSTRAINT "UserPreference_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
