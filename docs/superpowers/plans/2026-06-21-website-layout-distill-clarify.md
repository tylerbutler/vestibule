# Website Layout Distill Clarify Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Vestibule's website guide new users toward the right route shape, package sequence, and security responsibilities.

**Architecture:** Keep the existing Astro content-collection architecture. Edit the current homepage, package overview, quick-start MDX, and shared CSS instead of adding a new framework or broad navigation system. Reuse existing package metadata and add only page-local presentation data where needed.

**Tech Stack:** Astro 5, MDX, TypeScript-flavored Astro frontmatter, CSS custom properties, pnpm.

---

## File Structure

- Modify `website/src/pages/index.astro`: replace the broad integration-shape section with a route decision module; fix provider copy so GitHub is a provider package, not core.
- Modify `website/src/pages/docs/packages/index.astro`: turn package overview into a route-shape decision ledger plus provider add-on table.
- Modify `website/src/content/docs/quick-start.mdx`: attach security checkpoints to install, request/callback routing, core routing, and callback failure examples.
- Modify `website/src/styles/global.css`: add route-decision styles, reduce repeated card-like styling for provider/package comparison, remove routine yellow hover fills from secondary links.
- Verify with `cd website && pnpm build`.

Do not modify search behavior, content schemas, package APIs, or Starlight/Astro configuration.

---

### Task 1: Homepage Route Decision

**Files:**
- Modify: `website/src/pages/index.astro`
- Modify: `website/src/styles/global.css`

- [ ] **Step 1: Inspect the current homepage**

Run:

```bash
sed -n '1,220p' website/src/pages/index.astro
```

Expected: the file imports simple-icons, builds `supportedProviders`, defines `directFlow`, and has a section headed `Start with the integration shape.`

- [ ] **Step 2: Update homepage frontmatter data**

In `website/src/pages/index.astro`, remove this line:

```astro
const primaryPackages = packageEntries.slice(0, 3);
```

Replace the `supportedProviders` entry for GitHub with:

```astro
  {
    name: "GitHub",
    packageName: nameForPackage("github", "vestibule_github"),
    href: hrefForPackage("github"),
    note: "OAuth App sign-in with verified-primary-email lookup.",
    icon: siGithub
  },
```

Add this block after `supportedProviders`:

```astro
const routeChoices = [
  {
    label: "Recommended for Wisp and Mist",
    title: "Start with middleware",
    body:
      "Let Wisp or Mist own request and callback routes while your app maps the normalized auth result to a user session.",
    href: "/docs/quick-start#middleware-path",
    action: "Use middleware",
    meta: "Add core, one provider strategy, and the middleware package for your server layer."
  },
  {
    label: "Advanced path",
    title: "Use core when your app owns the auth routes",
    body:
      "Choose core APIs when you want direct control over redirects, callback storage, and framework integration.",
    href: "/docs/quick-start#core-path",
    action: "Use core directly",
    meta: "Store state and PKCE verifier yourself before redirecting."
  },
  {
    label: "After the base flow works",
    title: "Add provider packages",
    body:
      "Add GitHub, Google, Microsoft, or Apple strategies when your sign-in flow needs provider-specific profile behavior.",
    href: "/docs/packages#provider-strategies",
    action: "Choose providers",
    meta: "Provider packages extend the base flow; they do not replace route handling."
  }
];
```

- [ ] **Step 3: Replace the homepage integration section**

Replace the whole section that starts with:

```astro
  <section class="content-grid split">
```

and ends with its closing `</section>` after the `CodeBlock` with:

```astro
  <section class="route-decision" aria-labelledby="route-decision-heading">
    <div class="section-heading">
      <h2 id="route-decision-heading">Choose the route shape first.</h2>
      <p>
        Start with middleware when Wisp or Mist should own the auth routes. Use
        core only when your app handles routing, session storage, and callback
        data directly.
      </p>
    </div>
    <div class="route-choice-list">
      {routeChoices.map((choice, index) => (
        <a
          class:list={["route-choice", { recommended: index === 0 }]}
          href={choice.href}
        >
          <span class="path-label">{choice.label}</span>
          <strong>{choice.title}</strong>
          <span>{choice.body}</span>
          <small>{choice.meta}</small>
          <em>{choice.action}</em>
        </a>
      ))}
    </div>
  </section>

  <section class="content-grid split">
    <div>
      <h2>Keep the callback boundary explicit.</h2>
      <p>
        Vestibule creates the authorization request and validates the callback.
        Your app still stores state and PKCE data before redirecting, then maps
        successful auth results to accounts.
      </p>
    </div>
    <CodeBlock code={directFlow} lang="gleam" class="code-card" />
  </section>
```

- [ ] **Step 4: Replace the homepage package section**

Replace the whole `Packages by job` section with:

```astro
  <section>
    <div class="section-heading">
      <h2>Packages follow the route shape.</h2>
      <p>
        Pick the routing layer first, then add provider strategies for the
        identity providers your app supports.
      </p>
    </div>
    <div class="package-river">
      <a class="package-row" href={hrefForPackage("wisp")}>
        <span>
          <strong>{nameForPackage("wisp", "vestibule_wisp")}</strong>
          <small>Wisp middleware</small>
        </span>
        <span>Use when your Wisp app should own request and callback routing helpers.</span>
      </a>
      <a class="package-row" href={hrefForPackage("mist")}>
        <span>
          <strong>{nameForPackage("mist", "vestibule_mist")}</strong>
          <small>Mist middleware</small>
        </span>
        <span>Use when your app runs directly on Mist and wants the same auth ergonomics.</span>
      </a>
      <a class="package-row" href={hrefForPackage("core")}>
        <span>
          <strong>{nameForPackage("core", "vestibule")}</strong>
          <small>Core package</small>
        </span>
        <span>Use when your app owns routing, transient callback storage, and framework integration.</span>
      </a>
    </div>
  </section>
```

- [ ] **Step 5: Add homepage route CSS**

In `website/src/styles/global.css`, add this block after `.section-heading p`:

```css
.route-decision {
  margin: var(--space-12) 0;
}

.route-choice-list {
  display: grid;
  gap: var(--space-3);
}

.route-choice {
  display: grid;
  gap: var(--space-2);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--bg);
  color: var(--ink);
  padding: var(--space-5);
  text-decoration: none;
}

.route-choice.recommended {
  border-color: color-mix(in oklch, var(--primary) 52%, var(--border));
  background: var(--primary-soft);
}

.route-choice:hover,
.route-choice:focus-visible,
.route-choice:active {
  border-color: var(--primary);
}

.route-choice strong {
  color: var(--ink);
  font-size: var(--text-title);
  line-height: var(--line-title);
}

.route-choice > span:not(.path-label),
.route-choice small {
  color: var(--muted);
  line-height: var(--line-compact);
}

.route-choice em {
  color: var(--accent-ink);
  font-style: normal;
  font-weight: var(--weight-semibold);
}
```

- [ ] **Step 6: Add responsive route grid CSS**

In the existing `@media (min-width: 58rem)` block, add:

```css
  .route-choice-list {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
```

- [ ] **Step 7: Run a targeted build check**

Run:

```bash
cd website && pnpm build
```

Expected: Astro build succeeds.

- [ ] **Step 8: Commit homepage work**

Run:

```bash
git add website/src/pages/index.astro website/src/styles/global.css
git commit -m "docs: clarify website route decision"
```

Expected: commit succeeds. Do not add unrelated existing files such as `.mcp.json` or `.impeccable/critique/*`.

---

### Task 2: Package Overview Decision Ledger

**Files:**
- Modify: `website/src/pages/docs/packages/index.astro`
- Modify: `website/src/styles/global.css`

- [ ] **Step 1: Inspect package overview**

Run:

```bash
sed -n '1,130p' website/src/pages/docs/packages/index.astro
```

Expected: the file defines `middleware`, `providers`, and `core`, then renders core, middleware, and provider sections.

- [ ] **Step 2: Add route package data**

In `website/src/pages/docs/packages/index.astro`, add this after `const core = ...`:

```astro
const packageBySlug = new Map(packages.map((pkg) => [packageSlug(pkg), pkg]));
const routePackages = ["wisp", "mist", "core"]
  .map((slug) => packageBySlug.get(slug))
  .filter((pkg) => pkg !== undefined);
const routeLabel = (slug: string) =>
  slug === "wisp"
    ? "Recommended for Wisp apps"
    : slug === "mist"
      ? "Recommended for plain Mist apps"
      : slug === "core"
        ? "Advanced custom routing"
        : "Route package";
```

- [ ] **Step 3: Replace package overview sections**

Replace the core and middleware sections, from `{core && (` through the closing `</section>` for `middleware-packages`, with:

```astro
    <section id="core-package" class="route-decision">
      <div class="section-heading">
        <h2>Choose who owns the auth routes</h2>
        <p>
          Start with Wisp or Mist middleware when your server layer should own
          request and callback routes. Use core directly when your app owns that
          transport boundary.
        </p>
      </div>
      <div class="route-choice-list package-route-list">
        {routePackages.map((pkg) => {
          const slug = packageSlug(pkg);
          return (
            <a
              class:list={["route-choice", { recommended: slug === "wisp" || slug === "mist" }]}
              href={packageHref(pkg)}
            >
              <span class="path-label">{routeLabel(slug)}</span>
              <strong>{pkg.data.name}</strong>
              <span>{pkg.data.useWhen}</span>
              <small>{pkg.data.summary}</small>
              <em>Read package guide</em>
            </a>
          );
        })}
      </div>
    </section>
```

- [ ] **Step 4: Rename provider table framing**

In the provider section, replace:

```astro
        <h2>Provider strategies</h2>
        <p>Provider packages normalize profile data while preserving provider-specific security behavior.</p>
```

with:

```astro
        <h2>Add provider strategies after the route shape</h2>
        <p>
          Provider packages plug into the base request/callback flow. Choose them
          for the identity providers your app supports.
        </p>
```

Replace the table header row with:

```astro
            <th id="provider-package" scope="col">Provider package</th>
            <th id="provider-scopes" scope="col">Default scopes</th>
            <th id="provider-behavior" scope="col">Important behavior</th>
```

- [ ] **Step 5: Add package overview responsive CSS**

In `website/src/styles/global.css`, add this near the route CSS from Task 1:

```css
.package-route-list {
  margin-bottom: var(--space-12);
}
```

- [ ] **Step 6: Build package overview**

Run:

```bash
cd website && pnpm build
```

Expected: build succeeds. If TypeScript/Astro rejects the `filter` narrowing for `routePackages`, replace Step 2's `routePackages` definition with:

```astro
const routePackages = ["wisp", "mist", "core"].flatMap((slug) => {
  const pkg = packageBySlug.get(slug);
  return pkg ? [pkg] : [];
});
```

- [ ] **Step 7: Commit package overview work**

Run:

```bash
git add website/src/pages/docs/packages/index.astro website/src/styles/global.css
git commit -m "docs: improve package overview hierarchy"
```

Expected: commit succeeds.

---

### Task 3: Quick Start Security Checkpoints

**Files:**
- Modify: `website/src/content/docs/quick-start.mdx`
- Modify: `website/src/styles/global.css`

- [ ] **Step 1: Inspect quick-start path sections**

Run:

```bash
sed -n '147,280p' website/src/content/docs/quick-start.mdx
```

Expected: middleware path, core path, callback failure, and before-shipping sections are present.

- [ ] **Step 2: Replace the first scope note with a route decision note**

In `website/src/content/docs/quick-start.mdx`, replace the first `<p className="scope-note">...</p>` under `Let middleware own the auth routes` with:

```mdx
      <p className="scope-note">
        <strong>Start here for Wisp or Mist:</strong> middleware owns the
        request and callback routes. Add provider packages after this base flow
        works.
      </p>
```

- [ ] **Step 3: Add middleware security checkpoints**

After the middleware `CodeBlock` for `wispCode`, add:

```mdx
      <ul className="responsibility-list" aria-label="Middleware responsibilities before redirecting">
        <li>
          <strong>Initialize the state store once.</strong>
          Reusing it lets middleware bind callback data to the user flow.
        </li>
        <li>
          <strong>Delete callback data after success or failure.</strong>
          The middleware consumes one-time state; your app should not reuse a
          failed callback.
        </li>
        <li>
          <strong>Map <code>auth.uid</code> to your own account.</strong>
          Vestibule authenticates the provider identity; your app owns sessions.
        </li>
      </ul>
```

- [ ] **Step 4: Add core security checkpoints**

After the core `CodeBlock` for `coreCode`, add:

```mdx
      <ul className="responsibility-list warning" aria-label="Core flow responsibilities">
        <li>
          <strong>Store state and PKCE verifier server-side before redirecting.</strong>
          Bind them to the user's session and expire them quickly.
        </li>
        <li>
          <strong>Delete stored callback data after every result.</strong>
          Success, provider rejection, and state mismatch should all consume the
          stored values.
        </li>
        <li>
          <strong>Never assert the callback result.</strong>
          Stale tabs, denied consent, network errors, and forged state are normal
          runtime cases.
        </li>
      </ul>
```

- [ ] **Step 5: Replace callback failure response copy**

Replace the existing `How to respond` list with:

```mdx
      <ul className="check-list warning">
        <li>Discard the stored state and verifier on every failure.</li>
        <li>Restart the flow for stale tabs, reused links, and state mismatch.</li>
        <li>Offer retry only for transient network or code-exchange failures.</li>
        <li>Log the specific error server-side; show users a generic sign-in failure.</li>
      </ul>
```

- [ ] **Step 6: Tighten the final before-shipping checklist**

Replace the `<ul className="check-list">` inside `#security-responsibilities` with:

```mdx
   <ul className="check-list">
     <li>Production redirect URIs must use HTTPS.</li>
     <li>State and PKCE verifier values must be short-lived and server-side.</li>
     <li>Bearer tokens must be redacted from logs and error reports.</li>
     <li>Cookie-secret rotation invalidates in-flight OAuth callbacks.</li>
   </ul>
```

- [ ] **Step 7: Add responsibility list CSS**

In `website/src/styles/global.css`, update:

```css
.step-list,
.setup-list,
.check-list {
```

to:

```css
.step-list,
.setup-list,
.check-list,
.responsibility-list {
```

After the `.check-list.warning li::before` block, add:

```css
.responsibility-list {
  margin: var(--space-4) 0 0;
  border-radius: var(--radius-md);
  background: color-mix(in oklch, var(--primary-soft) 56%, var(--bg));
  padding: var(--space-4);
  list-style: none;
}

.responsibility-list.warning {
  background: var(--yellow-soft);
}

.responsibility-list li {
  color: var(--muted);
}

.responsibility-list strong {
  color: var(--ink);
}
```

- [ ] **Step 8: Build quick-start changes**

Run:

```bash
cd website && pnpm build
```

Expected: build succeeds.

- [ ] **Step 9: Commit quick-start work**

Run:

```bash
git add website/src/content/docs/quick-start.mdx website/src/styles/global.css
git commit -m "docs: clarify quick start responsibilities"
```

Expected: commit succeeds.

---

### Task 4: Distill Repeated Surfaces

**Files:**
- Modify: `website/src/styles/global.css`

- [ ] **Step 1: Inspect card-like surface styles**

Run:

```bash
grep -n "package-row\\|provider-link\\|compare-item\\|resource-links a:hover\\|search-suggestions a:hover" website/src/styles/global.css
```

Expected: styles for package rows, provider links, compare items, and yellow hover fills are present.

- [ ] **Step 2: Distill package rows**

Replace the `.package-row` block with:

```css
.package-row {
  display: grid;
  gap: var(--space-3);
  align-items: start;
  border-block-start: 1px solid var(--border);
  color: var(--ink);
  padding: var(--space-4) 0;
  text-decoration: none;
}
```

Replace `.package-row:hover` with:

```css
.package-row:hover {
  color: var(--accent-ink);
}
```

- [ ] **Step 3: Distill provider links**

Replace the `.provider-link` block with:

```css
.provider-link {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: var(--space-3);
  align-items: center;
  border-block-start: 1px solid var(--border);
  color: var(--ink);
  padding: var(--space-4) 0;
  text-decoration: none;
}
```

Replace the `.provider-link:hover, .provider-link:focus-visible, .provider-link:active` block with:

```css
.provider-link:hover,
.provider-link:focus-visible,
.provider-link:active {
  color: var(--accent-ink);
}
```

- [ ] **Step 4: Distill compare items**

Replace the `.compare-item` block with:

```css
.compare-item {
  display: grid;
  gap: var(--space-2);
  border-block-start: 1px solid var(--border);
  color: var(--ink);
  padding: var(--space-4) 0;
  text-decoration: none;
}
```

Replace the `.compare-item:hover, .compare-item:focus-visible, .compare-item:active` block with:

```css
.compare-item:hover,
.compare-item:focus-visible,
.compare-item:active {
  color: var(--accent-ink);
}
```

- [ ] **Step 5: Remove routine yellow hover fills**

Replace:

```css
.search-suggestions a:hover {
  background: var(--yellow);
  color: oklch(0.2 0.035 300);
}
```

with:

```css
.search-suggestions a:hover {
  background: var(--primary);
  color: var(--bg);
}
```

Replace:

```css
.resource-links a:hover {
  background: var(--yellow);
  color: oklch(0.2 0.035 300);
}
```

with:

```css
.resource-links a:hover {
  background: var(--primary);
  color: var(--bg);
}
```

- [ ] **Step 6: Build distilled styles**

Run:

```bash
cd website && pnpm build
```

Expected: build succeeds.

- [ ] **Step 7: Run detector**

Run:

```bash
node .agents/skills/impeccable/scripts/detect.mjs --json website/src
```

Expected: `[]`.

- [ ] **Step 8: Commit distilled styles**

Run:

```bash
git add website/src/styles/global.css
git commit -m "docs: distill website comparison surfaces"
```

Expected: commit succeeds.

---

### Task 5: Final Verification

**Files:**
- Verify: `website/src/pages/index.astro`
- Verify: `website/src/pages/docs/packages/index.astro`
- Verify: `website/src/content/docs/quick-start.mdx`
- Verify: `website/src/styles/global.css`

- [ ] **Step 1: Verify no stale GitHub core copy remains**

Run:

```bash
grep -Rni "GitHub in core\\|GitHub from core\\|Built into the core package" website/src
```

Expected: no matches.

- [ ] **Step 2: Verify yellow hover is not routine**

Run:

```bash
grep -n "a:hover" website/src/styles/global.css | grep -C 2 yellow || true
```

Expected: no routine link hover rules use `var(--yellow)`.

- [ ] **Step 3: Verify route and security copy exists**

Run:

```bash
grep -Rni "Start with middleware\\|Use core when\\|Store state and PKCE verifier\\|Discard the stored state" website/src/pages website/src/content/docs
```

Expected: matches in homepage/package overview/quick-start content.

- [ ] **Step 4: Build website**

Run:

```bash
cd website && pnpm build
```

Expected: build succeeds.

- [ ] **Step 5: Review git diff**

Run:

```bash
git --no-pager diff --stat HEAD~4..HEAD
git --no-pager status --short
```

Expected: four implementation commits are present. Status may still show unrelated pre-existing `.mcp.json` and `.impeccable/critique/`; do not stage them unless the user explicitly asks.

---

## Self-Review Notes

- Spec coverage: Task 1 and Task 2 cover route/package layout hierarchy; Task 3 covers security-copy clarification; Task 4 covers surface distillation and yellow hover reduction; Task 5 covers build/source verification.
- Out-of-scope items preserved: no search ranking/highlighting, no content schema changes, no Starlight migration, no library API changes.
- Type consistency: Astro snippets use existing helpers (`packageHref`, `packageSlug`, `hrefForPackage`, `nameForPackage`) and existing CSS tokens.
