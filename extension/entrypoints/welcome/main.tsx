import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Welcome } from '../../src/ui/Welcome';
import '../sidepanel/style.css';
import { applyCachedTheme } from '../../src/lib/settings';

applyCachedTheme();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Welcome />
  </StrictMode>,
);
