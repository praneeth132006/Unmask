/**
 * Protection inside Gmail, without opening the side panel:
 * - analyzes each email you open and shows a banner above risky ones
 * - badges risky senders in the inbox list
 * - asks "Wait, this goes to …" before a risky link opens
 * - warns when Reply would go to a different address than the sender
 * Everything runs locally. Dependencies are injected so it can be tested
 * against a fake Gmail page.
 */
import type { Report } from '../core/types';
import type { FetchRawResponse, GmailMessageRef, GmailState } from './messages';
import type { SenderHistory } from '../analyzers/history';
import type { ProtectionList } from '../analyzers/protection';
import { findMessageRoot } from './highlight';
import { BADGE_ATTR, BANNER_ATTR, PEEK_ATTR, confirmDialog, createBadge, createBanner, createPeekButton, showPeekCard, topReasons } from './inpage';
import { plainSummary } from '../core/plain';
import { peekPrivacyLines, verdictLabel } from '../core/facts';
import { linkWarning, pruneVerdicts, quickVerdict, replyWarning, type StoredVerdict } from './protect';
import { press } from './gmailActions';
import { debounceMax } from './schedule';

export interface ProtectSettings {
  gmailBanner: boolean;
  inboxBadges: boolean;
  clickProtection: boolean;
  senderHistory: boolean;
  /** "Peek" pill on inbox rows. */
  peekButtons?: boolean;
  /** Check unread rows automatically, before they're opened. */
  scanInbox?: boolean;
}

/** Where a mail web app keeps its messages. Gmail is the default; Outlook on the web has its own. */
export interface MailSite {
  /** Container of one open message. */
  findRoot(doc: Document, key: string): Element | null;
  /** The message container an element (link, button) sits in. */
  rootOf(el: Element): Element | null;
  keyOfRoot(root: Element): string;
  /** The rendered email body inside a message container. */
  bodyOf(root: Element): Element | null;
  /** Selector matching any rendered email body, for link clicks. */
  bodySelector: string;
  /** The open conversation's id, to remember its verdict for the inbox list. */
  threadId(doc: Document): string | null;
  /** Inbox list rows, when the site has them. */
  inboxRows?(doc: Document): { row: Element; sender: Element; address: string; name: string; thread: string }[];
  /** The message to download for an inbox row, so it can be checked without opening it. */
  refForRow?(row: Element, thread: string): GmailMessageRef | null;
  /** Unread rows in the list. */
  isUnread?(row: Element): boolean;
  /** Where the badge and Peek button go in a row, so they're always visible. */
  chipHost?(row: Element, sender: Element): Element | null;
}

export const GMAIL_SITE: MailSite = {
  findRoot: (doc, key) => findMessageRoot(doc, { permId: key.startsWith('msg-') ? key : null, legacyId: key.startsWith('msg-') ? null : key, fromName: '', fromEmail: '', subject: '' }),
  rootOf: (el) => el.closest('[data-message-id], [data-legacy-message-id]'),
  keyOfRoot: (root) => {
    const perm = root.getAttribute('data-message-id')?.replace(/^#/, '');
    return perm && perm.startsWith('msg-') ? perm : (root.getAttribute('data-legacy-message-id') ?? '');
  },
  bodyOf: (root) => root.querySelector('.a3s, [data-message-body]'),
  bodySelector: '.a3s, [data-message-body]',
  threadId: (doc) => doc.querySelector('h2[data-thread-perm-id]')?.getAttribute('data-thread-perm-id')?.replace(/^#/, '') ?? null,
  inboxRows: (doc) =>
    Array.from(doc.querySelectorAll('tr.zA')).flatMap((row) => {
      const sender = row.querySelector('[email]');
      if (!sender) return [];
      return [{
        row,
        sender,
        address: sender.getAttribute('email') ?? '',
        name: sender.getAttribute('name') ?? sender.textContent?.trim() ?? '',
        thread: row.querySelector('[data-thread-id]')?.getAttribute('data-thread-id')?.replace(/^#/, '') ?? '',
      }];
    }),
  // A thread's id is its first message's id: thread-f:N belongs to msg-f:N.
  refForRow: (row, thread) => {
    const n = thread.match(/^thread-([af]):(\d+)$/);
    // Prefer the conversation's latest message when Gmail exposes it; otherwise its first.
    const hex = (attr: string) => {
      const v = row.querySelector(`[${attr}]`)?.getAttribute(attr) ?? null;
      return v && /^[0-9a-f]+$/i.test(v) ? v : null;
    };
    const last = hex('data-legacy-last-non-draft-message-id') ?? hex('data-legacy-last-message-id');
    const legacy = last ?? hex('data-legacy-thread-id');
    if (!n && !legacy) return null;
    const subject = row.querySelector('.bog, .bqe, [data-thread-id]')?.textContent?.trim() ?? '';
    return { permId: last ? null : n ? `msg-${n[1]}:${n[2]}` : null, legacyId: legacy, fromName: '', fromEmail: '', subject };
  },
  isUnread: (row) => row.classList.contains('zE'),
  chipHost: (row) => row.querySelector('.xT') ?? row.querySelector('[data-thread-id]')?.closest('td') ?? null,
};

export interface ProtectDeps {
  /** Defaults to Gmail. */
  site?: MailSite;
  doc: Document;
  win: Window;
  readState: () => GmailState;
  fetchRaw: (ref: GmailMessageRef) => Promise<FetchRawResponse>;
  analyze: (raw: string, extras: AnalyzeExtras) => Promise<Report>;
  settings: () => ProtectSettings;
  loadHistory: () => Promise<SenderHistory>;
  loadProtection?: () => Promise<ProtectionList>;
  rememberSender: (report: Report) => Promise<void>;
  loadVerdicts: () => Promise<Record<string, StoredVerdict>>;
  saveVerdicts: (v: Record<string, StoredVerdict>) => Promise<void>;
  openPanel?: () => void;
  /** Opens the side panel on a message that was peeked at, not opened. */
  openPeekInPanel?: (ref: GmailMessageRef) => void;
  debounceMs?: number;
}

/** What the analysis needs besides the email itself. */
export interface AnalyzeExtras {
  history?: SenderHistory;
  protection?: ProtectionList;
}

const ROW_ATTR = 'data-unmask-row';
const CHIPS_ATTR = 'data-unmask-chips';
const BYPASS_ATTR = 'data-unmask-bypass';

export function messageKey(m: GmailMessageRef): string {
  return m.permId ?? m.legacyId ?? '';
}

const REPLY_LABEL = /^(reply|reply all|reply to all)$/i;

function replyButton(target: Element): Element | null {
  const el = target.closest('[role="button"], [role="link"], [role="menuitem"], .ams');
  if (!el) return null;
  const label = (el.getAttribute('aria-label') ?? el.getAttribute('data-tooltip') ?? el.textContent ?? '').trim();
  return REPLY_LABEL.test(label) ? el : null;
}

export function startProtection(deps: ProtectDeps): { stop: () => void; scan: () => Promise<void>; reports: Map<string, Report>; inboxStatus: () => { rows: number; peekButtons: number; peekEnabled: boolean } } {
  const { doc, win } = deps;
  const site = deps.site ?? GMAIL_SITE;
  const reports = new Map<string, Report>();
  const pending = new Set<string>();
  const dismissed = new Set<string>();
  let verdicts: Record<string, StoredVerdict> | null = null;
  let history: SenderHistory | undefined;
  let stopped = false;
  const later = debounceMax(() => void scan(), deps.debounceMs ?? 500, 1500);

  const getVerdicts = async (): Promise<Record<string, StoredVerdict>> => (verdicts ??= await deps.loadVerdicts().catch(() => ({})));

  function drawBanner(key: string, report: Report) {
    const s = deps.settings();
    const root = site.findRoot(doc, key);
    if (!root) return;
    const existing = root.querySelector(`[${BANNER_ATTR}]`);
    if (!s.gmailBanner || report.verdict === 'clear' || dismissed.has(key)) {
      existing?.remove();
      return;
    }
    if (existing) return;
    const body = site.bodyOf(root);
    if (!body?.parentElement) return;
    const plain = plainSummary(report);
    const banner = createBanner(doc, { verdict: report.verdict, score: report.score, headline: plain.headline, reasons: plain.reasons.length ? plain.reasons : topReasons(report.findings), onOpenPanel: deps.openPanel, onDismiss: () => dismissed.add(key) });
    body.parentElement.insertBefore(banner, body);
  }

  async function analyzeMessage(ref: GmailMessageRef, threadOverride?: string): Promise<Report | null> {
    const key = messageKey(ref);
    pending.add(key);
    try {
      const res = await deps.fetchRaw(ref);
      if (!res.ok) throw new Error(res.error);
      if (stopped) return null;
      const s = deps.settings();
      history = s.senderHistory ? await deps.loadHistory().catch(() => undefined) : undefined;
      const protection = await deps.loadProtection?.().catch(() => undefined);
      const report = await deps.analyze(res.raw, { history, protection });
      if (stopped) return null;
      reports.set(key, report);
      drawBanner(key, report);
      if (s.senderHistory) await deps.rememberSender(report).catch(() => {});
      const thread = threadOverride ?? site.threadId(doc);
      if (thread) {
        const v = await getVerdicts();
        const prev = v[thread];
        // A thread is as risky as its riskiest message.
        if (!prev || prev.score <= report.score || Date.now() - prev.at > 86_400_000) {
          verdicts = pruneVerdicts({ ...v, [thread]: { verdict: report.verdict, score: report.score, reasons: topReasons(report.findings), at: Date.now() } });
          await deps.saveVerdicts(verdicts).catch(() => {});
        }
      }
      return report;
    } catch (e) {
      // Gmail didn't give us the source; the side panel explains why when opened.
      if (threadOverride) throw e;
      return null;
    } finally {
      pending.delete(key);
    }
  }

  /** Checks an inbox row's email without opening it, and shows the result in a card. */
  async function peek(ref: GmailMessageRef, thread: string, sender: { name: string; address: string }) {
    const from = sender.name ? `${sender.name} <${sender.address}>` : sender.address;
    showPeekCard(doc, { state: 'loading', subject: ref.subject, from });
    try {
      const report = reports.get(messageKey(ref)) ?? (await analyzeMessage(ref, thread));
      if (!report) return;
      const plain = plainSummary(report);
      showPeekCard(doc, {
        state: 'done',
        subject: report.email.subject || ref.subject,
        from: report.email.from ? `${report.email.from.name ? `${report.email.from.name} ` : ''}<${report.email.from.address}>` : from,
        verdict: report.verdict,
        score: report.score,
        headline: plain.headline,
        reasons: plain.reasons,
        label: verdictLabel(report),
        privacy: peekPrivacyLines(report),
        preview: report.previewText,
        onReadSafely: deps.openPeekInPanel ? () => deps.openPeekInPanel!(ref) : undefined,
      });
      await badgeRows();
    } catch (e) {
      showPeekCard(doc, { state: 'error', subject: ref.subject, from, error: e instanceof Error ? e.message : String(e) });
    }
  }

  /** Unread rows checked automatically, one at a time, at most 15 per visit to a list. */
  const scanned = new Set<string>();
  let scanning = false;
  async function scanUnread(rows: { row: Element; thread: string }[]) {
    if (scanning) return;
    scanning = true;
    let checked = 0;
    try {
      for (const { row, thread } of rows) {
        if (stopped || !deps.settings().scanInbox || scanned.size >= 15) break;
        if (!thread || scanned.has(thread) || !(site.isUnread?.(row) ?? false)) continue;
        const v = await getVerdicts();
        if (v[thread]) continue;
        const ref = site.refForRow?.(row, thread);
        if (!ref) continue;
        scanned.add(thread);
        if (await analyzeMessage(ref, thread).catch(() => null)) checked++;
        await new Promise((r) => setTimeout(r, 400));
      }
    } finally {
      scanning = false;
    }
    // Re-badge only when something new was checked; badgeRows calls back into this function.
    if (checked) await badgeRows();
  }

  async function badgeRows() {
    const s = deps.settings();
    const rows = site.inboxRows?.(doc) ?? [];
    if (!s.inboxBadges && !s.peekButtons) {
      doc.querySelectorAll(`[${BADGE_ATTR}], [${PEEK_ATTR}], [${CHIPS_ATTR}]`).forEach((b) => b.remove());
      doc.querySelectorAll(`[${ROW_ATTR}]`).forEach((r) => r.removeAttribute(ROW_ATTR));
      return;
    }
    if (!rows.length) return;
    const v = await getVerdicts();
    if (s.senderHistory && !history) history = await deps.loadHistory().catch(() => undefined);
    for (const { row, sender, address, name, thread } of rows) {
      const stored = thread ? v[thread] : undefined;
      const result = stored ?? quickVerdict(name, address, history);
      const ref = s.peekButtons ? (site.refForRow?.(row, thread) ?? null) : null;
      const signature = `${address}|${thread}|${result.verdict}|${s.inboxBadges ? 1 : 0}|${ref ? 1 : 0}`;
      // Gmail redraws rows in place; the marker can outlive the elements it stands for.
      const intact = (!ref || row.querySelector(`[${PEEK_ATTR}]`)) && (!(s.inboxBadges && result.verdict !== 'clear') || row.querySelector(`[${BADGE_ATTR}]`));
      if (row.getAttribute(ROW_ATTR) === signature && intact) continue;
      row.setAttribute(ROW_ATTR, signature);
      row.querySelectorAll(`[${BADGE_ATTR}], [${PEEK_ATTR}], [${CHIPS_ATTR}]`).forEach((b) => b.remove());
      row.querySelectorAll(`[${CHIPS_ATTR}]`).forEach((c) => c.remove());
      const chips = doc.createElement('span');
      chips.setAttribute(CHIPS_ATTR, '');
      // Never shrink or wrap: Gmail clips long subjects, and our chips sit at the start.
      chips.style.cssText = 'display:inline-flex;align-items:center;flex:none;margin-right:6px;vertical-align:middle;white-space:nowrap;';
      if (s.inboxBadges && result.verdict !== 'clear') chips.append(createBadge(doc, result.verdict, result.reasons));
      if (ref) chips.append(createPeekButton(doc, () => void peek(ref, thread, { name, address })));
      if (!chips.childElementCount) continue;
      // Where Gmail puts its own label chips: the start of the subject, which is never cut off.
      // (Right after the sender name, Gmail's fixed-width column hid them.)
      const host = site.chipHost?.(row, sender) ?? sender.parentElement;
      host?.insertBefore(chips, host.firstChild);
    }
    if (s.scanInbox) void scanUnread(rows);
  }

  async function scan() {
    if (stopped) return;
    const s = deps.settings();
    if (s.gmailBanner || s.clickProtection) {
      let state: GmailState | null = null;
      try {
        state = deps.readState();
      } catch {
        state = null;
      }
      for (const ref of state?.messages ?? []) {
        const key = messageKey(ref);
        if (!key) continue;
        const report = reports.get(key);
        if (report) drawBanner(key, report);
        else if (!pending.has(key)) void analyzeMessage(ref);
      }
    }
    await badgeRows();
  }

  // ---- clicks ----------------------------------------------------------------
  async function onClick(e: MouseEvent) {
    if (stopped || e.button !== 0 || !(e.target instanceof Element)) return;
    const s = deps.settings();
    if (!s.clickProtection) return;
    const target = e.target;

    const reply = replyButton(target);
    if (reply) {
      if (reply.hasAttribute(BYPASS_ATTR)) return reply.removeAttribute(BYPASS_ATTR);
      const root = site.rootOf(reply);
      // The Reply bar under a thread belongs to its last message.
      const key = root ? site.keyOfRoot(root) : [...reports.keys()].pop();
      const report = key ? reports.get(key) : undefined;
      const w = report && replyWarning(report);
      if (!w) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      const go = await confirmDialog(doc, {
        title: 'Your reply will go somewhere else',
        target: w.replyTo,
        reasons: [`The email came from ${w.from}, but replies are set to go to ${w.replyTo}.`, 'Scammers do this so the real person never sees your answer.'],
        proceedLabel: 'Reply anyway',
      });
      if (go) {
        reply.setAttribute(BYPASS_ATTR, '');
        press(reply);
      }
      return;
    }

    const a = target.closest('a[href]');
    if (!a || !a.closest(site.bodySelector)) return;
    const root = site.rootOf(a);
    const report = root ? reports.get(site.keyOfRoot(root)) : undefined;
    if (!report) return;
    const href = a.getAttribute('href') ?? '';
    const w = linkWarning(report, href, a.getAttribute('data-saferedirecturl'));
    if (!w) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    const go = await confirmDialog(doc, { title: 'Wait, this link goes to', target: w.host, reasons: w.reasons, proceedLabel: 'Open anyway' });
    if (go) win.open(href, '_blank', 'noopener,noreferrer');
  }

  const listener = (e: Event) => void onClick(e as MouseEvent);
  doc.addEventListener('click', listener, true);
  const observer = new (win as unknown as { MutationObserver: typeof MutationObserver }).MutationObserver((records) => {
    // Our own banners and badges changing must not trigger another pass.
    if (records.every((r) => [...r.addedNodes, ...r.removedNodes].every((n) => n instanceof Element && (n.hasAttribute(BANNER_ATTR) || n.hasAttribute(BADGE_ATTR) || n.hasAttribute(PEEK_ATTR) || n.hasAttribute(CHIPS_ATTR) || n.hasAttribute('data-unmask-peek-card'))))) return;
    later.schedule();
  });
  observer.observe(doc.body, { childList: true, subtree: true });
  void scan();

  return {
    reports,
    scan,
    inboxStatus: () => ({ rows: site.inboxRows?.(doc).length ?? 0, peekButtons: doc.querySelectorAll(`[${PEEK_ATTR}]`).length, peekEnabled: deps.settings().peekButtons !== false }),
    stop() {
      stopped = true;
      later.cancel();
      observer.disconnect();
      doc.removeEventListener('click', listener, true);
      doc.querySelectorAll(`[${BANNER_ATTR}], [${BADGE_ATTR}], [${PEEK_ATTR}], [${CHIPS_ATTR}], [data-unmask-peek-card]`).forEach((n) => n.remove());
    },
  };
}
