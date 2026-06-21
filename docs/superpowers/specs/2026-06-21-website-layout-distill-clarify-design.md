# Website Layout, Distillation, and Clarification Design

## Goal

Improve the website's first-run documentation path without changing the site's Astro architecture, visual identity, or search behavior. The pass should help a new Gleam developer answer three questions quickly:

1. Which route shape should I start with?
2. Which packages do I add next?
3. Which security responsibilities still belong to my app?

## Scope

This design covers three requested areas:

- Layout: strengthen the route/package decision hierarchy across the homepage, package overview, and quick start.
- Distillation: reduce repeated card-like surfaces where a simpler ledger, list, or inline grouping communicates better.
- Clarification: move key security responsibility copy closer to the code and decisions it affects.

Search ranking, search highlighting, navigation restructuring, and a Starlight migration are out of scope.

## Recommended Approach

Use one consistent route-shape decision pattern across the main entry surfaces.

The site should make the recommended path explicit:

- Use middleware first when the app uses Wisp or Mist.
- Use core when the app owns routing, session storage, and callback handling.
- Add provider packages after the base request/callback flow works.

This keeps the current content model and page structure but makes the user's first decision more visible.

## Page-Level Design

### Homepage

Replace the current broad "integration shape" explanation with a stronger decision section. The section should present the route-shape choice first, then show provider packages as the next layer.

The homepage should still feel like a product overview, not a wizard. Use a compact decision module, not a large form or multi-step component.

### Package Overview

Make the package overview read less like a gallery and more like a decision ledger.

The core package should remain prominent, but middleware should carry the recommended first path for Wisp/Mist users. Provider packages should be framed as add-ons after route shape, not peer alternatives to the base integration decision.

### Quick Start

Keep middleware as the default path and core as the advanced path. Make this hierarchy clearer at the top of the page.

Attach compact security checkpoints near the code examples that create the relevant obligations:

- Store state and PKCE verifier server-side before redirecting.
- Delete transient callback data after success or failure.
- Treat state mismatch as hostile or stale; do not retry it with the same callback data.
- Log detailed errors server-side; show generic user-facing auth failure copy.

## Visual System Changes

Keep the existing tokens, colors, typography, and spacing scale.

Reduce visual sameness by separating component roles:

- Code, install, and security panels may keep bordered surfaces.
- Package and provider comparisons should use simpler ledger/list treatments.
- Purple-soft backgrounds should signal active, selected, recommended, or important guidance, not routine decoration.
- Yellow should remain a checkpoint/focus signal, not a routine hover fill for secondary links.

No gradient text, glassmorphism, side-stripe callouts, oversized radii, or decorative shadows should be introduced.

## Copy Direction

Use direct, specific developer copy.

Preferred language:

- "Start with middleware for Wisp or Mist."
- "Use core when your app owns the auth routes."
- "Add provider packages after the base flow works."
- "Store state and PKCE verifier server-side before redirecting."
- "Discard callback data after every failure."

Avoid abstract phrasing such as "integration shape" when the user needs an action.

## Components and Data Flow

No new content collection is required.

Implementation can use page-local data structures or lightweight markup in existing Astro pages. If a route-shape pattern appears in more than two places with the same structure, extract a small Astro component; otherwise keep the edit local to avoid needless abstraction.

Existing data flow remains:

- `website/src/data/content.ts` generates package navigation and package URLs.
- `website/src/content.config.ts` defines docs and package collection schemas.
- Package pages continue to read package metadata from `website/src/content/packages`.

## Accessibility and Responsiveness

All interactive targets must remain at least 44px high on coarse pointers.

The decision pattern must work in a single column on mobile and avoid hiding the recommended path behind a disclosure. Existing focus states, keyboard navigation, and reduced-motion behavior should remain unchanged.

Copy changes must preserve meaningful link text and avoid relying on color alone to indicate recommendation or warning.

## Testing and Verification

After implementation, run the website build from `website/` with `pnpm build`.

Also inspect the edited pages in source for:

- No repeated yellow hover fills on routine secondary links.
- No new inaccessible icon-only controls.
- No duplicated route-shape copy that contradicts another page.
- No stale references to GitHub being "built into core" if package metadata says otherwise.

## Non-Goals

- Do not migrate to Starlight.
- Do not redesign the command palette or search ranking.
- Do not change package metadata schemas unless the existing schema blocks the copy.
- Do not introduce a new design system or CSS framework.
- Do not change library APIs or package behavior.
