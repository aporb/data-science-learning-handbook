# UI/UX Design Review: Federal Data Science Learning Handbook

**Reviewer**: Claude Opus 4.6 (automated review)
**Date**: 2026-03-24
**Scope**: Site pages (index, chapter, platform), CSS/JS, and marketing visual assets

---

## Summary

The site demonstrates strong editorial design fundamentals: a well-defined design token system, a cohesive platform-inspired color palette, thoughtful typography choices, and polished dark mode implementation. The marketing assets are professionally structured for LinkedIn dimensions. The codebase is well-organized with clear separation of concerns.

That said, there are accessibility gaps, responsive edge cases, content mismatches between the site and marketing assets, and several opportunities to improve performance. This review documents 42 findings across all evaluated dimensions.

---

## Findings

### Visual Consistency

- **ID**: UX-001
- **Severity**: LOW
- **Component**: `site/css/style.css` (line 519) / `site/index.html` (line 519)
- **Finding**: Footer uses `#4A6FA5` as the fifth platform dot color, but this hex value does not correspond to any of the five declared platform CSS custom properties (`--palantir-blue: #1B2A4A`, `--databricks-red: #FF3621`, `--qlik-green: #009845`, `--jupiter-navy: #003B5C`, `--advana-gold: #C5A572`). This inconsistency breaks the palette story -- Palantir is `#1B2A4A`, not `#4A6FA5`.
- **Fix**: Replace `style="background:#4A6FA5"` with `style="background:#1B2A4A"` on the fifth footer dot in both `index.html` and `databricks.html`, or introduce a documented secondary Palantir shade if intentional.

---

- **ID**: UX-002
- **Severity**: LOW
- **Component**: `site/platforms/databricks.html` (lines 11-24)
- **Finding**: Platform-specific styles (`.platform-hero`, `.platform-facts`, etc.) are defined inline in a `<style>` tag rather than in the shared stylesheet. This means every platform page must duplicate these styles, risking drift between pages.
- **Fix**: Move platform page styles (`.platform-hero`, `.platform-eyebrow`, `.platform-hero-title`, `.platform-hero-desc`, `.platform-tags`, `.platform-tag-pill`, `.platform-facts`, `.platform-fact`, `.platform-fact-label`, `.platform-fact-value`) into `site/css/style.css` in a new "Platform Page" section.

---

- **ID**: UX-003
- **Severity**: MEDIUM
- **Component**: `marketing/assets/carousel_overview.html` (slide 3, lines 574-587)
- **Finding**: Chapter titles in the carousel do not match the actual site chapter titles. For example, carousel lists "Data Governance & Policy Frameworks" for Ch 02, but the site uses "Python and R Foundations for Federal Platforms". Similarly, Ch 03 is "Palantir Foundry: Pipelines & Ontologies" in the carousel but "Data Acquisition in the Federal Ecosystem" on the site. All 13 chapter titles are mismatched. This creates confusion for anyone who clicks through from LinkedIn.
- **Fix**: Update `carousel_overview.html` slide 3 chapter list to match the actual chapter titles from `site/index.html`.

---

- **ID**: UX-004
- **Severity**: LOW
- **Component**: `marketing/assets/hero_announcement.html` (line 367)
- **Finding**: The platform card for Advana uses the label "Advana (JUPITER)", conflating Advana and Jupiter as one item, while the site clearly separates them as two distinct platforms. This mismatch may confuse readers.
- **Fix**: Either list them separately (matching the site's 5-platform model) or clarify the parenthetical.

---

- **ID**: UX-005
- **Severity**: LOW
- **Component**: `marketing/assets/infographic_full.html` (line 484)
- **Finding**: The infographic header says "2024" (`Open Source . Federal Data Science . 2024`), but the site content references events through early 2026 (e.g., "Maven Smart System -- now a DoD Program of Record as of March 2026"). The year is stale.
- **Fix**: Update to "2026" or remove the year entirely.

---

### Responsive Design

- **ID**: UX-006
- **Severity**: HIGH
- **Component**: `site/css/style.css` (lines 1517-1620)
- **Finding**: The chapter layout uses a 3-column grid (`1fr minmax(0, var(--content-max)) 280px`) with `--content-max: 72ch`. On viewports between 901px and 1200px, the TOC is hidden but the grid still uses `1fr minmax(0, 1fr)`, which can cause the prose column to stretch beyond comfortable reading width since the `max-width: 68ch` on `.prose p` does not constrain the overall article padding area, potentially leaving orphaned whitespace on one side.
- **Fix**: At the 1200px breakpoint, set `.chapter-main { max-width: 72ch; margin: 0 auto; }` to center the content column when the TOC disappears.

---

- **ID**: UX-007
- **Severity**: MEDIUM
- **Component**: `site/css/style.css` (lines 1586-1620)
- **Finding**: At 600px breakpoint, `.nav-links` is hidden entirely (`display: none`). The only remaining navigation is the hamburger menu for the sidebar. However, the sidebar only contains chapter and platform links -- it does not include a "Home" link. A user on a chapter page at mobile width has no obvious way to navigate home except the brand logo.
- **Fix**: Add a "Home" link at the top of the sidebar nav in all chapter and platform HTML templates, or keep at least a minimal nav-links display at 600px.

---

- **ID**: UX-008
- **Severity**: MEDIUM
- **Component**: `site/css/style.css` (lines 383-386)
- **Finding**: Hero section uses `padding: 5rem 4rem 4rem`. At mobile (900px breakpoint) it drops to `padding: 3rem 1.5rem 2.5rem`, which is fine. But between 600-900px the `hero-stats` uses horizontal flex with `gap: 1.25rem` and five stat items, which may cause horizontal overflow on narrower tablet screens (around 600-700px) before the 600px breakpoint kicks in to make them vertical.
- **Fix**: Add `flex-wrap: wrap` to `.hero-stats` (already present) but also set `min-width: 0` on `.stat-item` and test at 650px to confirm no overflow.

---

- **ID**: UX-009
- **Severity**: LOW
- **Component**: `site/css/style.css` (lines 1527-1535)
- **Finding**: At 900px breakpoint, `--sidebar-width` is set to `0px` but the sidebar is hidden via `transform: translateX(-260px)` with a hardcoded 260px width rather than using the CSS variable. If `--sidebar-width` were ever changed from 260px, the transform would be out of sync.
- **Fix**: Use `transform: translateX(calc(-1 * var(--sidebar-width-actual)))` or simply keep the hardcoded value but add a comment noting it must match.

---

- **ID**: UX-010
- **Severity**: LOW
- **Component**: `site/css/style.css` (line 1417)
- **Finding**: `.site-footer` has `margin-left: var(--sidebar-width)` which correctly becomes 0 on mobile. However, this is set as a separate rule rather than being part of the `.main-content` flow. If someone adds a footer inside a chapter page's `main-content` (as `databricks.html` does), the footer gets the margin from both `.site-footer` class and the parent's margin, potentially causing misalignment.
- **Fix**: Verify that all footers in chapter/platform pages render at the correct width. In `databricks.html`, the footer is inside `.main-content` which already has `margin-left: var(--sidebar-width)`, so the footer's own `margin-left: var(--sidebar-width)` doubles the offset. Remove `margin-left` from `.site-footer` when it is a descendant of `.main-content`, or restructure so footer is always outside `main-content`.

---

### Accessibility

- **ID**: UX-011
- **Severity**: CRITICAL
- **Component**: `site/index.html` (line 132)
- **Finding**: The `<main>` element has `id="main-content"` but there is no skip-to-content link at the top of the page. Screen reader and keyboard users must tab through the entire nav and sidebar before reaching main content.
- **Fix**: Add `<a href="#main-content" class="sr-only" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;z-index:999;" onfocus="this.style.position='static';this.style.width='auto';this.style.height='auto';">Skip to main content</a>` as the first child of `<body>`. Better yet, use the existing `.sr-only` class and add `:focus` styles that make it visible.

---

- **ID**: UX-012
- **Severity**: HIGH
- **Component**: `site/index.html` (lines 149-170)
- **Finding**: The `.hero-stats` section uses `aria-label="Handbook statistics"` on the container, but individual stat items have no semantic structure. Screen readers will read "96K Words 13 Chapters..." as a run-on string with no pausing or context.
- **Fix**: Wrap each stat in a `<dl>` / `<dt>` / `<dd>` structure, or add `role="group"` with `aria-label` to each `.stat-item`.

---

- **ID**: UX-013
- **Severity**: HIGH
- **Component**: `site/css/style.css` (lines 1173-1182)
- **Finding**: Inline `<code>` elements use `color: var(--databricks-red)` which is `#FF3621`. Against `--bg-code: #F1F0EC`, the contrast ratio is approximately 3.7:1, failing WCAG AA for normal text (requires 4.5:1). The red is vibrant but too light for the background.
- **Fix**: Darken inline code color to `#CC2A17` or `#B8220F` for 4.5:1+ contrast. Also verify the dark mode override `#FF8070` against `rgba(255,255,255,0.06)` over `#0F1117` -- this is approximately `#161B26` background, giving roughly 5.5:1 which passes.

---

- **ID**: UX-014
- **Severity**: MEDIUM
- **Component**: `site/css/style.css` (lines 478-483)
- **Finding**: `.stat-label` uses `color: rgba(255,255,255,0.5)` on `--bg-hero: #1B2A4A`. The resulting contrast ratio is approximately 3.2:1, failing WCAG AA for the 12px uppercase text.
- **Fix**: Increase opacity to `rgba(255,255,255,0.65)` for approximately 4.7:1 contrast.

---

- **ID**: UX-015
- **Severity**: MEDIUM
- **Component**: `site/css/style.css` (line 452)
- **Finding**: `.hero-description` uses `color: rgba(255,255,255,0.72)` on `#1B2A4A`. At 18px font size (1.125rem), this qualifies as large text under WCAG, requiring only 3:1. The contrast is approximately 4.5:1, which passes. No action needed on this specific element, but documenting for completeness.
- **Fix**: No fix needed.

---

- **ID**: UX-016
- **Severity**: MEDIUM
- **Component**: `site/index.html` (lines 44-57)
- **Finding**: The theme toggle icon swap uses `style="display:none"` inline on the sun SVG. When JavaScript toggles the icon, it modifies inline `style.display`, but there is no `aria-live` region or announcement to inform screen reader users that the theme has changed.
- **Fix**: Add `aria-live="polite"` to a visually-hidden status element, and update its text content in `toggleTheme()` to announce "Dark mode enabled" or "Light mode enabled".

---

- **ID**: UX-017
- **Severity**: LOW
- **Component**: `site/index.html` (lines 212-384)
- **Finding**: Chapter cards use `role="listitem"` inside a container with `role="list"`, which is correct. However, the cards are `<a>` elements, meaning the entire card is a single link. The description text inside may be too long for comfortable screen reader link announcements.
- **Fix**: Consider adding `aria-label` to each card with a concise label like "Chapter 01: Introduction to Data Science in Government", so screen readers announce the short form rather than all inner text.

---

- **ID**: UX-018
- **Severity**: MEDIUM
- **Component**: `site/platforms/databricks.html` (line 87)
- **Finding**: `.platform-facts` uses `role="list"` and child elements use `role="listitem"`, but the container is a `<div>` not a list element. While the ARIA roles compensate, the structure would be more semantic as a `<dl>` (description list) since each fact is a label-value pair.
- **Fix**: Convert to `<dl>` with `<dt>` for labels and `<dd>` for values, or keep current structure but ensure it tests correctly with screen readers.

---

- **ID**: UX-019
- **Severity**: LOW
- **Component**: `site/index.html` (lines 93-122)
- **Finding**: Sidebar platform dots use inline `style="background:#C5A572"` etc. These colored dots have no text alternative and are marked `aria-hidden` only implicitly (they lack any aria attributes). The adjacent link text provides context, so this is acceptable, but the dots should be explicitly `aria-hidden="true"` for completeness.
- **Fix**: Add `aria-hidden="true"` to each `<span class="platform-dot">` element in the sidebar.

---

- **ID**: UX-020
- **Severity**: HIGH
- **Component**: `site/js/main.js` (lines 277-331)
- **Finding**: Dynamically created floating copy buttons for prose `<pre>` blocks use inline styles for all visual properties, including `color: rgba(255,255,255,0.5)` and `background: rgba(27,42,74,0.6)`. This creates a contrast issue: white text at 50% opacity on a semi-transparent dark background over a light `#F1F0EC` code block background yields poor contrast. The effective background color is approximately `#7A8BA3` with text `rgba(255,255,255,0.5)` yielding roughly 2.1:1 contrast.
- **Fix**: Move floating copy button styles to CSS and use `color: rgba(255,255,255,0.85)` with `background: rgba(27,42,74,0.85)` for the light theme. Alternatively, use a solid dark background.

---

### Dark Mode

- **ID**: UX-021
- **Severity**: MEDIUM
- **Component**: `site/js/main.js` (lines 10-16, 26-40) / `site/index.html` (lines 44-57)
- **Finding**: Theme initialization runs in `main.js` which is loaded at the bottom of `<body>`. This means on first load, the page renders with `data-theme="light"` (set in HTML) before JS executes and potentially switches to dark. This causes a flash of light theme (FOLT) for dark-mode users.
- **Fix**: Move the `initTheme()` IIFE to an inline `<script>` in `<head>` (before any CSS renders the page), or use a blocking script in `<head>` that sets `data-theme` before first paint.

---

- **ID**: UX-022
- **Severity**: LOW
- **Component**: `site/css/style.css` (lines 222-230)
- **Finding**: Dark mode active nav link uses `color: var(--advana-gold)` with `background: rgba(197,165,114,0.12)`. The gold-on-dark treatment is consistently applied across sidebar active state (line 336-340), TOC active state (line 898-901), and nav active state. This is good visual consistency.
- **Fix**: No fix needed. Documenting as positive finding.

---

- **ID**: UX-023
- **Severity**: LOW
- **Component**: `site/css/prism-theme.css` (lines 148-153)
- **Finding**: Dark mode comment color `#606876` on background `#161B26` has a contrast ratio of approximately 2.7:1, which may make code comments difficult to read. While comments are intentionally de-emphasized, this is below WCAG AA even for large text.
- **Fix**: Lighten to `#7A8290` for approximately 4:1 contrast while still maintaining the muted aesthetic.

---

- **ID**: UX-024
- **Severity**: LOW
- **Component**: `site/css/style.css`
- **Finding**: The `.platform-strip` has separate dark mode background (`rgba(0,0,0,0.3)`) defined at line 545-547. However, the platform badges' light-mode colors (e.g., `.platform-badge.palantir` using `color: var(--palantir-blue)` which is `#1B2A4A`) are dark text that works on light backgrounds but would be invisible on a dark background. The dark mode badge overrides (lines 606-634) correctly address this.
- **Fix**: No fix needed. Dark mode badge colors are properly handled.

---

### Code Blocks

- **ID**: UX-025
- **Severity**: MEDIUM
- **Component**: `site/platforms/databricks.html` (lines 334-339)
- **Finding**: Prism.js and language components are loaded from `cdnjs.cloudflare.com` CDN. The core `prism.min.js` and three language files (`prism-python.min.js`, `prism-sql.min.js`, `prism-bash.min.js`) are all separate HTTP requests with no `defer` or `async` attributes. They are render-blocking scripts at the bottom of body, but they still delay `DOMContentLoaded` and thus delay `main.js` initialization.
- **Fix**: Add `defer` to all Prism script tags, or bundle them into a single file. Also consider adding `integrity` attributes (SRI) for CDN security since this is a federal-audience site.

---

- **ID**: UX-026
- **Severity**: LOW
- **Component**: `site/css/prism-theme.css` / `site/css/style.css`
- **Finding**: The `.prose pre` block (style.css line 1191) has `border-radius: 10px` and `border: 1px solid var(--border-light)`. When used with `.code-block-wrapper`, the pre gets `border-radius: 0 0 10px 10px` and no top border (from prism-theme.css line 28-31). The two systems produce visually consistent results. However, standalone `<pre>` blocks in prose have the full rounded corners while wrapped blocks have the header-only top with squared-off top pre. This dual behavior is intentional and works well.
- **Fix**: No fix needed. Documenting as positive finding.

---

- **ID**: UX-027
- **Severity**: LOW
- **Component**: `site/css/style.css` (line 1221-1224)
- **Finding**: `.code-block-header` has `border: 1px solid var(--border-light)` and `border-bottom: none`. The pre below it has its own border. At the seam between header and pre, there could be a 1px gap on some browsers at certain zoom levels due to sub-pixel rendering.
- **Fix**: Use `margin-bottom: -1px` on `.code-block-header` or `border-top: none` on the adjacent `pre` to ensure seamless connection.

---

### Navigation

- **ID**: UX-028
- **Severity**: LOW
- **Component**: `site/index.html` (line 39)
- **Finding**: The "Platforms" nav link points to `#platforms`, which is an anchor on the same page. On chapter or platform subpages, this same link pattern would need to be `../index.html#platforms` to work correctly. In `databricks.html` (line 40), it correctly uses `../index.html#platforms`. Consistent and correct.
- **Fix**: No fix needed.

---

- **ID**: UX-029
- **Severity**: MEDIUM
- **Component**: `site/platforms/databricks.html` (lines 62-69)
- **Finding**: The Databricks page sidebar "Chapters" section only shows 4 of 13 chapters (01, 02, 04, 09). While this appears intentional (showing only related chapters), it could confuse users who expect to navigate to any chapter. The chapter page sidebar (01-introduction.html) shows all 13 chapters.
- **Fix**: Either show all 13 chapters in the platform page sidebar (matching chapter page behavior), or add a visual indicator like "Related Chapters" label and a "View all chapters" link.

---

- **ID**: UX-030
- **Severity**: LOW
- **Component**: `site/js/main.js` (lines 84-98)
- **Finding**: `initActiveNav()` uses `normalizedCurrent.endsWith(normalizedLink)` to detect active state. This could produce false positives if, e.g., a page path ends with a substring of another page path. For example, `foundations.html` would match both `02-python-r-foundations.html` and a hypothetical `advanced-foundations.html`. In practice this is unlikely with the current URL scheme but is fragile.
- **Fix**: Use exact path matching or ensure the comparison accounts for directory boundaries.

---

- **ID**: UX-031
- **Severity**: LOW
- **Component**: `site/chapters/01-introduction.html` (lines 110-116)
- **Finding**: Breadcrumb navigation is semantically well-structured with `aria-label="Breadcrumb"` and `aria-current="page"`. However, it uses `<nav>` inside `<article>` which is valid HTML5 but unusual. The breadcrumb separator uses `aria-hidden="true"`, which is correct.
- **Fix**: No fix needed. Good accessibility pattern.

---

### Marketing Assets -- Dimensions

- **ID**: UX-032
- **Severity**: HIGH
- **Component**: `marketing/assets/hero_announcement.html` (lines 27-28)
- **Finding**: The hero announcement asset is dimensioned at 1600x840px. LinkedIn recommended image sizes are 1200x627 (link share) or 1080x1080 (carousel/square). The 1600x840 dimensions are non-standard and will be cropped or scaled unpredictably by LinkedIn, potentially cutting off content on the right panel.
- **Fix**: Resize to 1200x627 for standard LinkedIn link share format. The two-column layout will need to be adjusted -- reduce right panel width and left panel padding proportionally.

---

- **ID**: UX-033
- **Severity**: LOW
- **Component**: `marketing/assets/chapter_card_01.html` (lines 31-32)
- **Finding**: Chapter card is correctly dimensioned at 1200x627px, matching LinkedIn link share format. Good.
- **Fix**: No fix needed.

---

- **ID**: UX-034
- **Severity**: LOW
- **Component**: `marketing/assets/carousel_overview.html` (lines 61-62)
- **Finding**: Carousel slides are correctly dimensioned at 1080x1080px, matching LinkedIn carousel/document format. Good.
- **Fix**: No fix needed.

---

- **ID**: UX-035
- **Severity**: MEDIUM
- **Component**: `marketing/assets/infographic_full.html` (lines 27, 33-34)
- **Finding**: Infographic is 1200px wide with `min-height: 2400px`. This is a long-scroll format intended for download/screenshot. It is not sized for any specific LinkedIn format. If shared as a LinkedIn image, it would be cropped. The intended use case (download or screenshot) should be documented.
- **Fix**: Add an HTML comment or document noting the intended capture method. Consider also providing a 1080x1080 cropped version of the key sections for LinkedIn carousel posting.

---

### Typography

- **ID**: UX-036
- **Severity**: LOW
- **Component**: `site/css/style.css` (lines 41-43)
- **Finding**: The font stack uses system fonts (`-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, `Inter`, etc.) with Georgia for serif. The `<link rel="preconnect" href="https://fonts.googleapis.com">` in `index.html` suggests Google Fonts was considered but no actual font import is used. The marketing assets import Inter and JetBrains Mono from Google Fonts, creating a typography mismatch: the site uses system sans-serif while marketing uses Inter.
- **Fix**: Either add an Inter import to the site for visual consistency with marketing materials, or remove the unused `<link rel="preconnect">` tag from `index.html` to avoid an unnecessary DNS lookup.

---

- **ID**: UX-037
- **Severity**: LOW
- **Component**: `site/css/style.css` (lines 1024-1030)
- **Finding**: `.prose p` uses `line-height: var(--leading-loose)` (1.9) with `max-width: 68ch`. The 1.9 line height is quite generous -- most editorial sites use 1.6-1.75 for body text. At 68ch width, the generous line height works well. However, the first paragraph override (`.prose > p:first-of-type`) changes font size to `var(--text-lg)` (1.125rem) but inherits the same 1.9 line height, which at the larger size creates even more vertical space than intended.
- **Fix**: Consider reducing `--leading-loose` to 1.8 or adding `line-height: 1.75` specifically to `.prose > p:first-of-type`.

---

- **ID**: UX-038
- **Severity**: LOW
- **Component**: `site/css/style.css` (lines 946-962)
- **Finding**: Chapter titles use `font-family: var(--font-serif)` (Georgia) with `font-weight: 400` and `letter-spacing: -0.02em`. This creates a refined, editorial feel. The serif/sans pairing (Georgia headings, system sans body) is consistent and effective. The `clamp()` sizing on both hero and chapter titles provides good fluid typography.
- **Fix**: No fix needed. Strong typographic choices.

---

### Performance

- **ID**: UX-039
- **Severity**: MEDIUM
- **Component**: `site/index.html` (line 10)
- **Finding**: `<link rel="preconnect" href="https://fonts.googleapis.com">` is present but no Google Fonts stylesheet is actually loaded. This creates an unnecessary TLS connection. The browser spends time connecting to a server it never fetches from.
- **Fix**: Remove the `<link rel="preconnect">` tag, or add the actual Google Font import if Inter is desired.

---

- **ID**: UX-040
- **Severity**: MEDIUM
- **Component**: `marketing/assets/*.html` (all four files)
- **Finding**: All marketing assets use `@import url('https://fonts.googleapis.com/css2?family=...')` inside `<style>` blocks. CSS `@import` is render-blocking and slower than `<link>` tags. For static screenshot-capture assets this is less critical, but it delays rendering if opened in browser.
- **Fix**: Replace `@import` with `<link rel="stylesheet" href="https://fonts.googleapis.com/...">` in `<head>` for faster font loading, or accept the trade-off since these are screenshot-capture assets.

---

- **ID**: UX-041
- **Severity**: LOW
- **Component**: `site/platforms/databricks.html` (lines 334-339)
- **Finding**: Six external scripts are loaded sequentially at the bottom of body: mermaid (CDN), mermaid-init (local), prism core (CDN), prism-python (CDN), prism-sql (CDN), prism-bash (CDN), main.js (local). That is 4 CDN requests plus 2 local. The mermaid library alone is ~1.5MB minified.
- **Fix**: Consider lazy-loading mermaid only on pages that contain `.mermaid` elements, and bundling the three Prism components into a single file. Add `defer` attributes to non-critical scripts.

---

- **ID**: UX-042
- **Severity**: LOW
- **Component**: `site/js/main.js` (line 442)
- **Finding**: `setTimeout(wrapMermaidDiagrams, 600)` uses a fixed 600ms delay to wait for Mermaid rendering. This is a race condition -- on slow connections, Mermaid may not have rendered in 600ms; on fast connections, it wastes 600ms.
- **Fix**: Use a `MutationObserver` to detect when mermaid has rendered SVGs, or listen for mermaid's `run()` callback/promise if using mermaid 11+.

---

## Prioritized Fix List

### Critical (fix immediately)
1. **UX-011**: Add skip-to-content link for keyboard/screen reader navigation

### High (fix before launch)
2. **UX-013**: Fix inline `<code>` color contrast (WCAG AA failure)
3. **UX-020**: Fix floating copy button contrast on light backgrounds
4. **UX-032**: Resize hero announcement to 1200x627 for LinkedIn compatibility
5. **UX-012**: Add semantic structure to hero stats for screen readers

### Medium (fix soon)
6. **UX-021**: Move theme initialization to `<head>` to prevent flash of light theme
7. **UX-003**: Update carousel chapter titles to match actual site content
8. **UX-006**: Center chapter content column when TOC is hidden (1200px breakpoint)
9. **UX-007**: Add Home link to sidebar or keep minimal nav at 600px
10. **UX-014**: Increase hero stat-label opacity for contrast compliance
11. **UX-016**: Add screen reader announcement for theme toggle
12. **UX-018**: Consider `<dl>` structure for platform facts
13. **UX-025**: Add `defer`/SRI to CDN scripts, consider bundling Prism
14. **UX-029**: Clarify partial chapter list in platform page sidebar
15. **UX-039**: Remove unused `preconnect` tag or add actual font import
16. **UX-040**: Replace CSS `@import` with `<link>` in marketing assets
17. **UX-023**: Lighten dark mode code comment color for readability
18. **UX-008**: Verify hero stats flex-wrap at tablet breakpoints
19. **UX-035**: Document infographic capture method, consider LinkedIn-sized crops

### Low (fix when convenient)
20. **UX-001**: Fix fifth footer dot color to match platform palette
21. **UX-002**: Move platform page inline styles to shared CSS
22. **UX-004**: Align Advana/Jupiter naming in hero announcement
23. **UX-005**: Update infographic year from 2024 to 2026
24. **UX-009**: Document sidebar width/transform coupling
25. **UX-010**: Verify footer margin-left stacking in chapter pages
26. **UX-017**: Add aria-labels to chapter cards for concise announcements
27. **UX-019**: Add explicit aria-hidden to sidebar platform dots
28. **UX-027**: Fix potential sub-pixel gap between code header and pre
29. **UX-030**: Improve active nav path matching robustness
30. **UX-036**: Remove unused preconnect or import Inter for site/marketing consistency
31. **UX-037**: Consider reducing prose line-height from 1.9 to 1.8
32. **UX-041**: Lazy-load mermaid, bundle Prism components
33. **UX-042**: Replace setTimeout with MutationObserver for mermaid wrapping

### Positive Findings (no action needed)
- UX-015: Hero description contrast passes for large text
- UX-022: Dark mode active state colors are consistently applied
- UX-024: Dark mode platform badge colors properly handled
- UX-026: Code block dual-style system (standalone vs. wrapped) works well
- UX-028: Platform nav links correctly use relative paths
- UX-031: Breadcrumb accessibility pattern is well-implemented
- UX-033: Chapter card dimensions correct for LinkedIn
- UX-034: Carousel slide dimensions correct for LinkedIn
- UX-038: Typography pairing is effective and editorial

---

## Overall Assessment

**Design Quality**: 8/10 -- Strong editorial identity, cohesive palette, professional marketing assets.

**Responsive Design**: 7/10 -- Three well-chosen breakpoints (1200, 900, 600px) cover the major cases. Edge cases between breakpoints need attention.

**Accessibility**: 5/10 -- Missing skip link (critical), multiple contrast failures, limited screen reader announcements for interactive elements. Solid ARIA usage on nav and sidebar elements.

**Dark Mode**: 8/10 -- Comprehensive token-based implementation. Flash of wrong theme on load is the main issue.

**Code Blocks**: 8/10 -- Well-styled, copy buttons work, Prism theme matches palette. Minor CDN optimization opportunities.

**Navigation**: 7/10 -- Logical sidebar + top nav + prev/next structure. Mobile sidebar lacks Home link. Platform page sidebar inconsistently filtered.

**Marketing Assets**: 7/10 -- Professional design, correct dimensions for carousel and chapter cards. Hero announcement oversized. Content drift from actual site (chapter titles, dates, platform naming).

**Performance**: 6/10 -- Multiple CDN calls, unused preconnect, fixed-delay mermaid wrapping, render-blocking CSS imports in marketing assets. The site itself is lightweight (no frameworks), which is a strength.
