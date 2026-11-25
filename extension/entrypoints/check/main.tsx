import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { CheckMessage } from '../../src/ui/CheckMessage';
import '../sidepanel/style.css';
import { applyCachedTheme } from '../../src/lib/settings';

applyCachedTheme();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <CheckMessage />
  </StrictMode>,
);
