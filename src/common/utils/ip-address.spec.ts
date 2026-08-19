import { isPrivateIpAddress, normalizeIpAddress } from './ip-address';

describe('IP address utilities', () => {
  it('normalizes IPv4-mapped IPv6 addresses', () => {
    expect(normalizeIpAddress('::ffff:8.8.8.8')).toBe('8.8.8.8');
  });

  it.each(['10.0.0.1', '172.16.0.1', '192.168.1.1', '::1', 'fc00::1'])(
    'identifies %s as non-public',
    (address) => {
      expect(isPrivateIpAddress(address)).toBe(true);
    },
  );

  it('allows a public address to be looked up', () => {
    expect(isPrivateIpAddress('8.8.8.8')).toBe(false);
  });
});
