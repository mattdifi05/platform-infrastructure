export function unusedCssClasses(cssFiles, readText, sourceText) {
  const definedClasses = new Set();

  for (const file of cssFiles) {
    const source = readText(file).replace(/\/\*[\s\S]*?\*\//g, "");
    for (const match of source.matchAll(/\.(-?[_a-zA-Z]+[_a-zA-Z0-9-]*)/g)) {
      const className = match[1];
      if (isUiCssClass(className)) definedClasses.add(className);
    }
  }

  return [...definedClasses]
    .filter((className) => !isCssClassUsed(className, sourceText))
    .sort();
}

function isUiCssClass(className) {
  return /^(?:button|checkbox|choice|custom|date|field|is|loader|modal|pill|radio|range|scroll|status|surface|switch|sx|ui)-/.test(className);
}

function isCssClassUsed(className, sourceText) {
  const has = (token) => sourceText.includes(token);
  if (has(className)) return true;
  if (className.startsWith("modal-panel-") && has("modal-panel-${size}")) return true;
  if (["is-entered", "is-entering", "is-exiting"].includes(className) && has("`is-${revealPresence}`")) return true;
  if (["ui-block-expandable", "ui-block-static", "ui-block-steps"].includes(className) && has("`ui-block-card ui-block-${variant}")) return true;
  if (className.startsWith("is-filter-") && has("is-filter-${filterId}")) return true;
  if (/^is-step-\d+$/.test(className) && has("is-step-${currentStep + 1}")) return true;
  if (className.startsWith("has-icon-tone-") && has("has-icon-tone-${resolvedIconTone}")) return true;
  if (/^is-(?:brand|country|date|email|language)$/.test(className) && has("is-${resolvedIconTone}")) return true;
  if (/^is-(?:accent|danger|green|muted|surface|yellow)$/.test(className) && has("ui-token is-${tone}")) return true;
  if (/^is-(?:blocking|error|info|warning)$/.test(className) && has("field-message\", `is-${issue.severity}`")) return true;
  if (/^is-\d+$/.test(className) && has("is-${")) return true;
  return /^is-(?:cyan|danger|edit|muted|plain|primary|rose|slate|teal|violet|warning|good|warn|info|neutral|error)$/.test(className);
}
