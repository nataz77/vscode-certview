import '@fluentui/web-components/badge.js';
import '@fluentui/web-components/divider.js';
import '@fluentui/web-components/text.js';
import { setTheme } from '@fluentui/web-components/theme/set-theme.js';
import { webDarkTheme, webLightTheme } from '@fluentui/tokens';

function applyTheme(): void {
  const light = document.body.classList.contains('vscode-light') ||
    document.body.classList.contains('vscode-high-contrast-light');
  setTheme(light ? webLightTheme : webDarkTheme);
}

applyTheme();

new MutationObserver(applyTheme).observe(document.body, {
  attributes: true,
  attributeFilter: ['class']
});
