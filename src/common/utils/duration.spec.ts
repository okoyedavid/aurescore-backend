import { durationToSeconds } from './duration';

describe('durationToSeconds', () => {
  it.each([
    ['15m', 900],
    ['1d', 86_400],
    ['2w', 1_209_600],
  ])('converts %s to seconds', (value, expected) => {
    expect(durationToSeconds(value)).toBe(expected);
  });

  it('rejects invalid or zero durations', () => {
    expect(() => durationToSeconds('15 minutes')).toThrow();
    expect(() => durationToSeconds('0m')).toThrow();
  });
});
