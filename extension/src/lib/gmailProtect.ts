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
import { findMessageRoot } from './highlight';
import { BADGE_ATTR, BANNER_ATTR, confirmDialog, createBadge, createBanner, topReasons } from './inpage';
import { linkWarning, pruneVerdicts, quickVerdict, replyWarning, type StoredVerdict } from './protect';
import { press } from './gmailActions';

export interface ProtectSettings {
  gmailBanner: boolean;
  inboxBadges: boolean;
  clickProtection: boolean;
  senderHistory: boolean;
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
};

export interface ProtectDeps {
  /** Defaults to Gmail. */
  site?: MailSite;
  doc: Document;
  win: Window;
  readState: () => GmailState;
  fetchRaw: (ref: GmailMessageRef) => Promise<FetchRawResponse>;
  analyze: (raw: string, history: SenderHistory | undefined) => Promise<Report>;
  settings: () => ProtectSettings;
  loadHistory: () => Promise<SenderHistory>;
  rememberSender: (report: Report) => Promise<void>;
  loadVerdicts: () => Promise<Record<string, StoredVerdict>>;
  saveVerdicts: (v: Record<string, StoredVerdict>) => Promise<void>;
  openPanel?: () => void;
  debounceMs?: number;
}

const ROW_ATTR = 'data-unmask-row';
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

export function startProtection(deps: ProtectDeps): { stop: () => void; scan: () => Promise<void>; reports: Map<string, Report> } {
  const { doc, win } = deps;
  const site = deps.site ?? GMAIL_SITE;
  const reports = new Map<string, Report>();
  const pending = new Set<string>();
  const dismissed = new Set<string>();
  let verdicts: Record<string, StoredVerdict> | null = null;
  let history: SenderHistory | undefined;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

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
    const banner = createBanner(doc, { verdict: report.verdict, score: report.score, reasons: topReasons(report.findings), onOpenPanel: deps.openPanel, onDismiss: () => dismissed.add(key) });
    body.parentElement.insertBefore(banner, body);
  }

  async function analyzeMessage(ref: GmailMessageRef) {
    const key = messageKey(ref);
    pending.add(key);
    try {
      const res = await deps.fetchRaw(ref);
      if (!res.ok || stopped) return;
      const s = deps.settings();
      history = s.senderHistory ? await deps.loadHistory().catch(() => undefined) : undefined;
      const report = await deps.analyze(res.raw, history);
      if (stopped) return;
      reports.set(key, report);
      drawBanner(key, report);
      if (s.senderHistory) await deps.rememberSender(report).catch(() => {});
      const thread = site.threadId(doc);
      if (thread) {
        const v = await getVerdicts();
        const prev = v[thread];
        // A thread is as risky as its riskiest message.
        if (!prev || prev.score <= report.score || Date.now() - prev.at > 86_400_000) {
          verdicts = pruneVerdicts({ ...v, [thread]: { verdict: report.verdict, score: report.score, reasons: topReasons(report.findings), at: Date.now() } });
          await deps.saveVerdicts(verdicts).catch(() => {});
        }
      }
    } catch {
      // Gmail didn't give us the source; the side panel explains why when opened.
    } finally {
      pending.delete(key);
    }
  }

  async function badgeRows() {
    const s = deps.settings();
    const rows = site.inboxRows?.(doc) ?? [];
    if (!s.inboxBadges) {
      doc.querySelectorAll(`[${BADGE_ATTR}]`).forEach((b) => b.remove());
      doc.querySelectorAll(`[${ROW_ATTR}]`).forEach((r) => r.removeAttribute(ROW_ATTR));
      return;
    }
    if (!rows.length) return;
    const v = await getVerdicts();
    if (s.senderHistory && !history) history = await deps.loadHistory().catch(() => undefined);
    for (const { row, sender, address, name, thread } of rows) {
      const stored = thread ? v[thread] : undefined;
      const result = stored ?? quickVerdict(name, address, history);
      const signature = `${address}|${thread}|${result.verdict}`;
      if (row.getAttribute(ROW_ATTR) === signature) continue;
      row.setAttribute(ROW_ATTR, signature);
      row.querySelectorAll(`[${BADGE_ATTR}]`).forEach((b) => b.remove());
      if (result.verdict === 'clear') continue;
      sender.parentElement?.insertBefore(createBadge(doc, result.verdict, result.reasons), sender.nextSibling);
    }
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
    if (records.every((r) => [...r.addedNodes, ...r.removedNodes].every((n) => n instanceof Element && (n.hasAttribute(BANNER_ATTR) || n.hasAttribute(BADGE_ATTR))))) return;
    clearTimeout(timer);
    timer = setTimeout(() => void scan(), deps.debounceMs ?? 500);
  });
  observer.observe(doc.body, { childList: true, subtree: true });
  void scan();

  return {
    reports,
    scan,
    stop() {
      stopped = true;
      clearTimeout(timer);
      observer.disconnect();
      doc.removeEventListener('click', listener, true);
      doc.querySelectorAll(`[${BANNER_ATTR}], [${BADGE_ATTR}]`).forEach((n) => n.remove());
    },
  };
}
