# Cross Device Validation Matrix

| Target | Scope | Required evidence |
| --- | --- | --- |
| Chrome Windows | Full automated e2e, visual, accessibility and internal product flows | Playwright Chromium desktop pass |
| Edge Windows | Manual smoke plus visual review | Host app surface, UI catalog, overlay stack |
| Safari macOS | Cross-browser smoke, keyboard and overlay review | Playwright WebKit desktop pass plus manual Safari pass |
| Safari iOS | Touch, zoom, modal and form review | Manual device or simulator pass |
| Chrome Android | Touch, density, form and overlay review | Mobile Chromium visual pass plus manual Android pass |
| Firefox desktop | Cross-browser smoke and keyboard review | Playwright Firefox desktop pass |

Manual validation must record browser version, OS version, viewport, theme, density and tester initials before go-live.
