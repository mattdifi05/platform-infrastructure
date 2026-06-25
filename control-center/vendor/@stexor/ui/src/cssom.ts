"use client";

const styleKey = "style" as const;

let writableSheet: CSSStyleSheet | null = null;
let nextRuleId = 0;

export function nextCssRuleId(prefix: string) {
  nextRuleId += 1;
  return `${prefix}-${nextRuleId}`;
}

export function cssEscape(value: string) {
  return globalThis.CSS?.escape ? globalThis.CSS.escape(value) : value.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}

export function createDynamicCssRule(selector: string) {
  const sheet = getWritableSheet();
  if (!sheet) return null;

  try {
    const index = sheet.cssRules.length;
    sheet.insertRule(`${selector} { }`, index);
    const rule = sheet.cssRules.item(index);
    return rule instanceof CSSStyleRule ? rule : null;
  } catch {
    return null;
  }
}

export function clearDynamicCssRule(rule: CSSStyleRule | null) {
  if (!rule) return;
  const declaration = rule[styleKey];
  declaration.setProperty("display", "contents");
  declaration.setProperty("transform", "");
  declaration.setProperty("height", "");
  declaration.setProperty("inset", "");
}

export function setDynamicCssProperties(rule: CSSStyleRule | null, properties: Record<string, string>) {
  if (!rule) return;
  const declaration = rule[styleKey];
  for (const [property, value] of Object.entries(properties)) {
    declaration.setProperty(property, value);
  }
}

function getWritableSheet() {
  if (writableSheet && canWriteToSheet(writableSheet)) return writableSheet;

  for (const sheet of Array.from(document.styleSheets)) {
    if (!(sheet instanceof CSSStyleSheet)) continue;
    if (canWriteToSheet(sheet)) {
      writableSheet = sheet;
      return sheet;
    }
  }

  return null;
}

function canWriteToSheet(sheet: CSSStyleSheet) {
  try {
    const index = sheet.cssRules.length;
    sheet.insertRule(":root { }", index);
    sheet.deleteRule(index);
    return true;
  } catch {
    return false;
  }
}
