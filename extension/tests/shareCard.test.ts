import { describe, expect, it } from 'vitest';
import { defang, shareText, wrapLines } from '../src/ui/shareCard';
import { analyzeRawEmail } from '../src/core/analyze';
import { EXAMPLE_EMAIL } from '../src/demo/example';

describe('share card', () => {
  it('wraps text to the width and marks a cut with an ellipsis', () => {
    const measure = (s: string) => s.length;
    expect(wrapLines(measure, 'one two three four', 9)).toEqual(['one two', 'three', 'four']);
    const cut = wrapLines(measure, 'aa bb cc dd ee ff', 5, 2);
    expect(cut).toHaveLength(2);
    expect(cut[1]).toMatch(/…$/);
  });

  it('never writes a clickable address', async () => {
    expect(defang('paypa1-secure.top')).toBe('paypa1-secure[.]top');
    const text = shareText(await analyzeRawEmail(EXAMPLE_EMAIL));
    expect(text).toContain('paypa1-support[.]example');
    expect(text).not.toMatch(/billing@paypa1-support\.example/);
    expect(text).toMatch(/on my own device/);
  });
});
