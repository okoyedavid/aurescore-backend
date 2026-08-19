-- CreateEnum
CREATE TYPE "OAuthClientType" AS ENUM ('CONFIDENTIAL_WEB');

-- AlterTable
ALTER TABLE "OAuthClient"
ADD COLUMN "clientSecretHint" TEXT NOT NULL,
ADD COLUMN "clientType" "OAuthClientType" NOT NULL DEFAULT 'CONFIDENTIAL_WEB',
ADD COLUMN "description" TEXT,
ADD COLUMN "firstParty" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN "homepageUrl" TEXT,
ADD COLUMN "logoUrl" TEXT,
ADD COLUMN "ownerUserId" TEXT NOT NULL,
ADD COLUMN "secretCreatedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- AlterTable
ALTER TABLE "OAuthGrant"
ADD COLUMN "subject" TEXT NOT NULL,
ADD COLUMN "updatedAt" TIMESTAMPTZ(3) NOT NULL;

-- CreateIndex
CREATE INDEX "OAuthClient_ownerUserId_idx" ON "OAuthClient"("ownerUserId");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthGrant_subject_key" ON "OAuthGrant"("subject");

-- AddForeignKey
ALTER TABLE "OAuthClient"
ADD CONSTRAINT "OAuthClient_ownerUserId_fkey"
FOREIGN KEY ("ownerUserId") REFERENCES "User"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
