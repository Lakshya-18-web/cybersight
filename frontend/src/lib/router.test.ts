import { describe, expect, it } from 'vitest';
import { findRoute, matchPath } from './router';

describe('matchPath', () => {
  it('matches the root only for "/"', () => {
    expect(matchPath('/', '/')).toEqual({});
    expect(matchPath('/', '/alerts')).toBeNull();
  });
  it('matches static paths exactly and ignores a trailing slash', () => {
    expect(matchPath('/alerts', '/alerts')).toEqual({});
    expect(matchPath('/alerts', '/alerts/')).toEqual({});
    expect(matchPath('/alerts', '/alerts/new')).toBeNull();
  });
  it('captures and decodes params', () => {
    expect(matchPath('/cases/:id', '/cases/abc-123')).toEqual({ id: 'abc-123' });
    expect(matchPath('/cases/:id', '/cases/a%20b')).toEqual({ id: 'a b' });
  });
  it('rejects a malformed escape instead of throwing', () => {
    expect(matchPath('/cases/:id', '/cases/%E0%A4%A')).toBeNull();
  });
  it('does not let a param swallow extra segments', () => {
    expect(matchPath('/cases/:id', '/cases/a/b')).toBeNull();
  });
});

describe('findRoute', () => {
  const routes = [
    { path: '/alerts', title: 'Alerts', render: () => null },
    { path: '/alerts/new', title: 'New', render: () => null },
    { path: '/cases/:id', title: 'Case', render: () => null },
  ];
  it('prefers the more specific static route listed first', () => {
    expect(findRoute(routes, '/alerts/new')?.route.title).toBe('New');
  });
  it('returns params', () => {
    expect(findRoute(routes, '/cases/7')?.params).toEqual({ id: '7' });
  });
  it('returns null when nothing matches', () => {
    expect(findRoute(routes, '/nope')).toBeNull();
  });
});
