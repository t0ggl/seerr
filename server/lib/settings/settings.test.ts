import Settings from '@server/lib/settings';
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

describe('Settings OIDC Environment Configuration', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.OIDC_LOGIN_ENABLED;
    delete process.env.OIDC_ENABLED;
    delete process.env.OIDC_LOGIN;
    delete process.env.OIDC_PROVIDERS;
    delete process.env.OIDC_ISSUER_URL;
    delete process.env.OIDC_CLIENT_ID;
    delete process.env.OIDC_CLIENT_SECRET;
    delete process.env.OIDC_PROVIDER_NAME;
    delete process.env.OIDC_NAME;
    delete process.env.OIDC_PROVIDER_SLUG;
    delete process.env.OIDC_SLUG;
    delete process.env.OIDC_SCOPES;
    delete process.env.OIDC_LOGO;
    delete process.env.OIDC_REQUIRED_CLAIMS;
    delete process.env.OIDC_ADMIN_GROUP;
    delete process.env.OIDC_GROUP_CLAIM;
    delete process.env.OIDC_NEW_USER_LOGIN;
    delete process.env.APPLICATION_URL;
    delete process.env.APP_URL;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('configures a single OIDC provider via discrete env vars', () => {
    process.env.OIDC_ISSUER_URL = 'https://id.example.com';
    process.env.OIDC_CLIENT_ID = 'test-client-id';
    process.env.OIDC_CLIENT_SECRET = 'test-client-secret';
    process.env.OIDC_PROVIDER_NAME = 'Pocket ID';
    process.env.OIDC_PROVIDER_SLUG = 'pocketid';

    const settings = new Settings();
    assert.equal(settings.main.oidcLogin, true);
    assert.equal(settings.oidc.providers.length, 1);

    const provider = settings.oidc.providers[0];
    assert.equal(provider.slug, 'pocketid');
    assert.equal(provider.name, 'Pocket ID');
    assert.equal(provider.issuerUrl, 'https://id.example.com');
    assert.equal(provider.clientId, 'test-client-id');
    assert.equal(provider.clientSecret, 'test-client-secret');
    assert.equal(provider.scopes, 'openid profile email');
    assert.equal(provider.newUserLogin, true);
  });

  it('configures multiple OIDC providers via OIDC_PROVIDERS JSON env var', () => {
    process.env.OIDC_PROVIDERS = JSON.stringify([
      {
        slug: 'authentik',
        name: 'Authentik SSO',
        issuerUrl: 'https://auth.example.com/application/o/seerr/',
        clientId: 'authentik-client',
        clientSecret: 'authentik-secret',
        scopes: 'openid email profile groups',
        newUserLogin: false,
      },
      {
        slug: 'google',
        name: 'Google Workspace',
        issuerUrl: 'https://accounts.google.com',
        clientId: 'google-client',
        clientSecret: 'google-secret',
      },
    ]);

    const settings = new Settings();
    assert.equal(settings.main.oidcLogin, true);
    assert.equal(settings.oidc.providers.length, 2);

    assert.equal(settings.oidc.providers[0].slug, 'authentik');
    assert.equal(settings.oidc.providers[0].name, 'Authentik SSO');
    assert.equal(settings.oidc.providers[0].newUserLogin, false);

    assert.equal(settings.oidc.providers[1].slug, 'google');
    assert.equal(settings.oidc.providers[1].name, 'Google Workspace');
    assert.equal(settings.oidc.providers[1].newUserLogin, true);
  });

  it('respects explicit OIDC_LOGIN_ENABLED=false override', () => {
    process.env.OIDC_ISSUER_URL = 'https://id.example.com';
    process.env.OIDC_CLIENT_ID = 'test-client';
    process.env.OIDC_LOGIN_ENABLED = 'false';

    const settings = new Settings();
    assert.equal(settings.main.oidcLogin, false);
    assert.equal(settings.oidc.providers.length, 1);
  });

  it('sets applicationUrl from APPLICATION_URL env var', () => {
    process.env.APPLICATION_URL = 'https://seerr.example.com';

    const settings = new Settings();
    assert.equal(settings.main.applicationUrl, 'https://seerr.example.com');
  });

  it('configures adminGroup and groupClaim via discrete env vars', () => {
    process.env.OIDC_ISSUER_URL = 'https://id.example.com';
    process.env.OIDC_CLIENT_ID = 'test-client';
    process.env.OIDC_ADMIN_GROUP = 'admin';
    process.env.OIDC_GROUP_CLAIM = 'roles';

    const settings = new Settings();
    assert.equal(settings.oidc.providers[0].adminGroup, 'admin');
    assert.equal(settings.oidc.providers[0].groupClaim, 'roles');
  });

  it('configures adminGroup and groupClaim via OIDC_PROVIDERS JSON', () => {
    process.env.OIDC_PROVIDERS = JSON.stringify([
      {
        slug: 'authentik',
        issuerUrl: 'https://auth.example.com',
        clientId: 'authentik-client',
        adminGroup: 'seerr-admins',
        groupClaim: 'custom.groups',
      },
    ]);

    const settings = new Settings();
    assert.equal(settings.oidc.providers[0].adminGroup, 'seerr-admins');
    assert.equal(settings.oidc.providers[0].groupClaim, 'custom.groups');
  });

  it('applies OIDC_ADMIN_GROUP to existing providers', () => {
    process.env.OIDC_ADMIN_GROUP = 'administrators';
    const settings = new Settings();
    settings.load({
      oidc: {
        providers: [
          {
            slug: 'oidc',
            name: 'OIDC',
            issuerUrl: 'https://example.com',
            clientId: 'client',
            clientSecret: 'secret',
          },
        ],
      },
    });

    assert.equal(settings.oidc.providers[0].adminGroup, 'administrators');
  });
});
