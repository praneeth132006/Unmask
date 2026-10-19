import PostalMime from 'postal-mime';
import type { Address } from 'postal-mime';
import type { Mailbox, ParsedAttachment, ParsedEmail } from './types';

function toMailbox(addr: Address | undefined | null): Mailbox | null {
  if (!addr) return null;
  // Groups ("Team: a@x, b@y;") — use the first member.
  const box = addr.group ? addr.group[0] : addr;
  if (!box?.address) return null;
  const address = box.address.trim();
  const at = address.lastIndexOf('@');
  return {
    name: (box.name ?? '').trim(),
    address,
    domain: at >= 0 ? address.slice(at + 1).toLowerCase().replace(/\.$/, '') : '',
  };
}

function toMailboxes(list: Address[] | undefined): Mailbox[] {
  return (list ?? []).flatMap((a) => (a.group ? a.group : [a])).map(toMailbox).filter((m): m is Mailbox => m !== null);
}

function toBytes(content: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (typeof content === 'string') return new TextEncoder().encode(content);
  return content instanceof Uint8Array ? content : new Uint8Array(content);
}

/** Gmail's "Show original" page and copy/paste often lose the CR in CRLF; postal-mime handles both. */
export async function parseEmail(raw: string | ArrayBuffer | Uint8Array): Promise<ParsedEmail> {
  const email = await PostalMime.parse(raw, { attachmentEncoding: 'arraybuffer' });

  const attachments: ParsedAttachment[] = email.attachments.map((a, i) => {
    const content = toBytes(a.content);
    return {
      filename: a.filename ?? `attachment-${i + 1}`,
      mimeType: a.mimeType,
      size: content.byteLength,
      disposition: a.disposition,
      contentId: a.contentId,
      related: Boolean(a.related),
      content,
    };
  });

  const returnPath = email.returnPath?.replace(/^<|>$/g, '').trim() || null;

  return {
    headers: email.headers.map((h) => ({ key: h.key, name: h.originalKey ?? h.key, value: h.value })),
    from: toMailbox(email.from),
    sender: toMailbox(email.sender),
    replyTo: toMailboxes(email.replyTo),
    returnPath,
    to: toMailboxes(email.to),
    subject: email.subject ?? '',
    date: email.date ?? null,
    messageId: email.messageId ?? null,
    html: email.html ?? null,
    text: email.text ?? null,
    attachments,
  };
}

export function getHeaders(email: ParsedEmail, key: string): string[] {
  const k = key.toLowerCase();
  return email.headers.filter((h) => h.key === k).map((h) => h.value);
}
