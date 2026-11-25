/** DOMParser from linkedom, for runtimes without a DOM (the CLI, the Gmail add-on). Where atob may be missing, load a base64 shim first: linkedom's dependencies need it while loading. */
import { DOMParser as LinkeDOMParser } from 'linkedom';

const g = globalThis as Record<string, unknown>;
if (!g.DOMParser) g.DOMParser = LinkeDOMParser;
if (!g.NodeFilter) g.NodeFilter = { FILTER_ACCEPT: 1, FILTER_REJECT: 2, FILTER_SKIP: 3, SHOW_ALL: 0xffffffff, SHOW_ELEMENT: 0x1, SHOW_TEXT: 0x4, SHOW_COMMENT: 0x80 };
if (!g.Node) g.Node = { ELEMENT_NODE: 1, TEXT_NODE: 3, COMMENT_NODE: 8, DOCUMENT_NODE: 9 };
export {};
