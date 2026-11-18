// Where each screenshot lives under docs/images, by name, so new screenshots
// land in the right folder without a list to keep up to date.
//   inbox/    warnings inside Gmail and Outlook
//   panel/    the Unmask panel: summary, sender, links, body, privacy, headers
//   files/    attachments and the Documents tab
//   reports/  investigation reports and real examples
//   teams/    protection lists and rollout
//   settings/ settings and setup
//   start/    the welcome tab and practice
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

export function imageFolder(name) {
  if (/^(gmail|inbox|highlight)-/.test(name)) return 'inbox';
  if (/^(welcome|practice)-/.test(name)) return 'start';
  if (/^teams-|^settings-protection/.test(name)) return 'teams';
  if (/^panel-(files|documents)/.test(name)) return 'files';
  if (/^(report-|example-|panel-report)/.test(name)) return 'reports';
  if (/^(settings|setup)-/.test(name)) return 'settings';
  return 'panel';
}

/** Full path for a screenshot, creating its folder. */
export function imagePath(root, name) {
  const dir = join(root, imageFolder(name));
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}
