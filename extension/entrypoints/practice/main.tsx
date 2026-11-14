import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Practice } from '../../src/ui/Practice';
import '../sidepanel/style.css';
import { applyCachedTheme } from '../../src/lib/settings';

applyCachedTheme();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Practice />
  </StrictMode>,
);
