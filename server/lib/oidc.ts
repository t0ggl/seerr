import type { User } from '@server/entity/User';
import { Permission } from '@server/lib/permissions';
import { get } from 'lodash';

/**
 * Extracts group or role names from OIDC user claims.
 *
 * If a custom groupClaim is provided, it extracts values from that claim path
 * (supports dot-notation for nested paths such as "realm_access.roles").
 * Otherwise, it searches common group and role claim locations:
 * - "groups"
 * - "roles"
 * - "realm_access.roles" (Keycloak)
 */
export const extractGroupsFromUserInfo = (
  userInfo: Record<string, unknown>,
  groupClaim?: string
): string[] => {
  let values: unknown;

  if (groupClaim) {
    values = get(userInfo, groupClaim);
  } else {
    values =
      userInfo['groups'] ??
      userInfo['roles'] ??
      get(userInfo, 'realm_access.roles');
  }

  if (!values) {
    return [];
  }

  if (Array.isArray(values)) {
    return values.flatMap((v) => {
      if (typeof v === 'string') {
        return [v];
      }
      if (
        v &&
        typeof v === 'object' &&
        'name' in v &&
        typeof (v as { name: unknown }).name === 'string'
      ) {
        return [(v as { name: string }).name];
      }
      return [];
    });
  }

  if (typeof values === 'string') {
    return values
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  return [];
};

/**
 * Checks whether the user belongs to the specified admin group in their OIDC claims.
 * Performs a case-insensitive match and normalizes leading slashes (e.g. "/admin" vs "admin").
 */
export const hasOidcAdminGroup = (
  userInfo: Record<string, unknown>,
  adminGroup: string,
  groupClaim?: string
): boolean => {
  if (!adminGroup) {
    return false;
  }

  const groups = extractGroupsFromUserInfo(userInfo, groupClaim);
  const normalizedTarget = adminGroup.trim().toLowerCase().replace(/^\//, '');

  return groups.some((group) => {
    const normalizedGroup = group.trim().toLowerCase().replace(/^\//, '');
    return normalizedGroup === normalizedTarget;
  });
};

/**
 * Synchronizes admin permissions for a user based on whether they have the OIDC admin group.
 *
 * - If hasAdminGroup is true, grants Permission.ADMIN if not already present.
 * - If hasAdminGroup is false, revokes Permission.ADMIN if present (safeguarding User ID 1).
 *
 * Returns true if the user's permissions were modified, false otherwise.
 */
export const syncOidcAdminPermission = (
  user: User,
  hasAdminGroup: boolean
): boolean => {
  const isCurrentlyAdmin = (user.permissions & Permission.ADMIN) !== 0;

  if (hasAdminGroup && !isCurrentlyAdmin) {
    user.permissions |= Permission.ADMIN;
    return true;
  } else if (!hasAdminGroup && isCurrentlyAdmin) {
    // Never revoke admin privileges from User ID 1 (system owner)
    if (user.id === 1) {
      return false;
    }
    user.permissions &= ~Permission.ADMIN;
    return true;
  }

  return false;
};

/**
 * Synchronizes email for a user based on OIDC user claims.
 *
 * If email is provided and differs from the user's current email, updates user.email.
 * Returns true if the user's email was modified, false otherwise.
 */
export const syncOidcUserEmail = (
  user: User,
  email?: string | null
): boolean => {
  if (!email) {
    return false;
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (user.email !== normalizedEmail) {
    user.email = normalizedEmail;
    return true;
  }

  return false;
};
