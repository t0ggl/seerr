import { User } from '@server/entity/User';
import {
  extractGroupsFromUserInfo,
  hasOidcAdminGroup,
  syncOidcAdminPermission,
} from '@server/lib/oidc';
import { Permission } from '@server/lib/permissions';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

describe('OIDC group utilities', () => {
  describe('extractGroupsFromUserInfo', () => {
    it('extracts groups from default "groups" array', () => {
      const userInfo = { groups: ['users', 'admin', 'plex'] };
      assert.deepEqual(extractGroupsFromUserInfo(userInfo), [
        'users',
        'admin',
        'plex',
      ]);
    });

    it('extracts groups from default "roles" array if groups is absent', () => {
      const userInfo = { roles: ['member', 'admin'] };
      assert.deepEqual(extractGroupsFromUserInfo(userInfo), [
        'member',
        'admin',
      ]);
    });

    it('extracts groups from Keycloak "realm_access.roles" if groups/roles absent', () => {
      const userInfo = {
        realm_access: {
          roles: ['offline_access', 'admin'],
        },
      };
      assert.deepEqual(extractGroupsFromUserInfo(userInfo), [
        'offline_access',
        'admin',
      ]);
    });

    it('extracts groups from custom groupClaim including nested paths', () => {
      const userInfo = {
        custom: {
          team_roles: ['lead', 'admin'],
        },
      };
      assert.deepEqual(
        extractGroupsFromUserInfo(userInfo, 'custom.team_roles'),
        ['lead', 'admin']
      );
    });

    it('handles comma-separated string claim values', () => {
      const userInfo = { groups: 'users, admin, overseerr' };
      assert.deepEqual(extractGroupsFromUserInfo(userInfo), [
        'users',
        'admin',
        'overseerr',
      ]);
    });

    it('handles object arrays with name property', () => {
      const userInfo = {
        groups: [{ name: 'admin' }, { name: 'users' }],
      };
      assert.deepEqual(extractGroupsFromUserInfo(userInfo), ['admin', 'users']);
    });

    it('returns empty array if no group claims exist', () => {
      assert.deepEqual(extractGroupsFromUserInfo({}), []);
    });
  });

  describe('hasOidcAdminGroup', () => {
    it('returns true when user has exact admin group', () => {
      const userInfo = { groups: ['users', 'admin'] };
      assert.equal(hasOidcAdminGroup(userInfo, 'admin'), true);
    });

    it('handles case-insensitivity', () => {
      const userInfo = { groups: ['Users', 'ADMIN'] };
      assert.equal(hasOidcAdminGroup(userInfo, 'admin'), true);
      assert.equal(hasOidcAdminGroup(userInfo, 'Admin'), true);
    });

    it('normalizes Keycloak leading slash in group paths', () => {
      const userInfo = { groups: ['/admin', '/users/moderators'] };
      assert.equal(hasOidcAdminGroup(userInfo, 'admin'), true);
      assert.equal(hasOidcAdminGroup(userInfo, '/admin'), true);
    });

    it('returns false when user does not have admin group', () => {
      const userInfo = { groups: ['users', 'moderator'] };
      assert.equal(hasOidcAdminGroup(userInfo, 'admin'), false);
    });

    it('returns false when adminGroup is empty', () => {
      const userInfo = { groups: ['admin'] };
      assert.equal(hasOidcAdminGroup(userInfo, ''), false);
    });
  });

  describe('syncOidcAdminPermission', () => {
    it('grants admin permission when member and not already admin', () => {
      const user = new User({
        id: 2,
        permissions: Permission.REQUEST,
      });

      const modified = syncOidcAdminPermission(user, true);
      assert.equal(modified, true);
      assert.equal((user.permissions & Permission.ADMIN) !== 0, true);
      assert.equal((user.permissions & Permission.REQUEST) !== 0, true);
    });

    it('does not modify user when member and already admin', () => {
      const user = new User({
        id: 2,
        permissions: Permission.ADMIN | Permission.REQUEST,
      });

      const modified = syncOidcAdminPermission(user, true);
      assert.equal(modified, false);
      assert.equal((user.permissions & Permission.ADMIN) !== 0, true);
    });

    it('revokes admin permission when not member and currently admin', () => {
      const user = new User({
        id: 2,
        permissions: Permission.ADMIN | Permission.REQUEST,
      });

      const modified = syncOidcAdminPermission(user, false);
      assert.equal(modified, true);
      assert.equal((user.permissions & Permission.ADMIN) === 0, true);
      assert.equal((user.permissions & Permission.REQUEST) !== 0, true);
    });

    it('does not modify user when not member and not admin', () => {
      const user = new User({
        id: 2,
        permissions: Permission.REQUEST,
      });

      const modified = syncOidcAdminPermission(user, false);
      assert.equal(modified, false);
      assert.equal((user.permissions & Permission.ADMIN) === 0, true);
    });

    it('never revokes admin from User ID 1 (owner)', () => {
      const user = new User({
        id: 1,
        permissions: Permission.ADMIN | Permission.REQUEST,
      });

      const modified = syncOidcAdminPermission(user, false);
      assert.equal(modified, false);
      assert.equal((user.permissions & Permission.ADMIN) !== 0, true);
    });
  });
});
