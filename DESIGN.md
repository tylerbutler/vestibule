---
name: Vestibule
description: Strategy-based OAuth2 authentication for Gleam
colors:
  brand-purple: "oklch(0.420 0.180 302)"
  brand-purple-hover: "oklch(0.360 0.170 302)"
  brand-purple-soft: "oklch(0.930 0.050 302)"
  threshold-yellow: "oklch(0.880 0.160 94)"
  background: "oklch(1.000 0.000 0)"
  surface: "oklch(0.975 0.006 300)"
  ink: "oklch(0.200 0.035 300)"
  muted: "oklch(0.440 0.035 300)"
  border: "oklch(0.890 0.018 300)"
  danger: "oklch(0.550 0.180 27)"
typography:
  display:
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "2.25rem"
    fontWeight: 700
    lineHeight: 1.05
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "1.5rem"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  title:
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "1.125rem"
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "0.875rem"
    fontWeight: 650
    lineHeight: 1.25
rounded:
  sm: "6px"
  md: "10px"
  lg: "14px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "40px"
components:
  button-primary:
    backgroundColor: "{colors.brand-purple}"
    textColor: "{colors.background}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "12px 18px"
  button-primary-hover:
    backgroundColor: "{colors.brand-purple-hover}"
    textColor: "{colors.background}"
  button-secondary:
    backgroundColor: "{colors.threshold-yellow}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "12px 18px"
  chip-provider:
    backgroundColor: "{colors.brand-purple-soft}"
    textColor: "{colors.brand-purple}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "6px 10px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: "24px"
---

# Design System: Vestibule

## 1. Overview

**Creative North Star: "The Secure Threshold"**

Vestibule's visual system should feel like a calm, well-lit entry checkpoint: the outside world is complex, provider-specific, and risky; the inside is structured, readable, and safe. Purple carries the authentication infrastructure and product identity. Yellow acts as the checkpoint light: rare, high-signal, and used to call attention to the next action or an important security responsibility.

This is product UI and developer documentation, not a campaign surface. It should look precise enough for security-sensitive work and approachable enough for copy-paste integration. It explicitly rejects the PRODUCT.md anti-reference: "loud SaaS growth marketing." It also rejects flashy gradients, gimmicky identity-provider spectacle, mascots, over-animation, exaggerated metrics, and generic auth-dashboard theatrics.

**Key Characteristics:**
- Restrained purple/yellow identity, never rainbow OAuth decoration.
- High-contrast text and controls for trust-critical reading.
- System typography that feels native to developer tools and Hex docs.
- Flat-by-default surfaces with depth conveyed through tone, borders, and state.
- Short, direct copy around security responsibilities and recovery paths.

## 2. Colors

The palette is restrained product purple with yellow used as a deliberate signal, not a decorative wash.

### Primary
- **Vestibule Purple** (`brand-purple`): The primary brand and action color. Use for primary buttons, active navigation, focused provider choices, and concise identity moments. White text on this color passes contrast comfortably.
- **Vestibule Purple Hover** (`brand-purple-hover`): The pressed and hover state for primary actions. It should feel firmer, not louder.
- **Soft Vestibule Purple** (`brand-purple-soft`): A pale purple support surface for provider chips, selected rows, and informational callouts that need brand continuity without visual weight.

### Secondary
- **Threshold Yellow** (`threshold-yellow`): The logo-derived signal accent. Use sparingly for secondary CTAs, warning-adjacent guidance, focus halos, and "next step" highlights. Pair with `ink`, not white, so the accent stays readable.

### Neutral
- **White Background** (`background`): The default canvas. Do not warm-tint the whole page; the warmth comes from yellow, not the body background.
- **Quiet Surface** (`surface`): A barely-purple panel surface for code-adjacent cards, example containers, and grouped settings.
- **Purple Ink** (`ink`): The default text color, tuned toward the brand hue while staying near-black.
- **Muted Ink** (`muted`): Secondary text, captions, and helper copy. It remains dark enough for body-adjacent text.
- **Soft Border** (`border`): Dividers, input borders, and table rules.
- **Failure Red** (`danger`): Authentication failures and destructive states. It should not compete with purple or yellow for brand ownership.

### Named Rules

**The Checkpoint Light Rule.** Yellow is a signal, not a surface. If more than one element in a small viewport is filled with yellow, choose the single most important action and make the rest neutral.

**The Purple Does the Work Rule.** Purple owns primary actions, selected states, and identity. Do not introduce blue, cyan, or green as competing brand accents unless the meaning is explicitly semantic.

**The White Hall Rule.** Keep the default background pure white. Avoid cream, parchment, beige, or warm-neutral body backgrounds; they make the yellow logo color feel generic instead of intentional.

## 3. Typography

**Display Font:** system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif  
**Body Font:** system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif  
**Label/Mono Font:** use the host documentation/code renderer's monospace stack for code only.

**Character:** One native sans family is the right fit for this product register: familiar, fast, and unshowy. Code blocks may use monospace, but labels, buttons, tables, and headings should stay in the same sans vocabulary.

### Hierarchy
- **Display** (700, 2.25rem, 1.05 line-height): Product and example-page headings. Keep letter spacing no tighter than -0.025em.
- **Headline** (650, 1.5rem, 1.2 line-height): Section headings in docs, demo pages, and settings-like surfaces.
- **Title** (650, 1.125rem, 1.3 line-height): Cards, form groups, and table section titles.
- **Body** (400, 1rem, 1.6 line-height): Documentation prose, helper text, and explanatory UI copy. Cap long prose at 65-75ch.
- **Label** (650, 0.875rem, 1.25 line-height): Buttons, field labels, status chips, and compact navigation. Avoid tiny all-caps tracked labels as repeated section scaffolding.

### Named Rules

**The Native Tool Rule.** Product UI should feel like a reliable developer tool, not a poster. Avoid decorative display fonts, oversized clamp headings, and novelty type treatments.

**The Security Copy Rule.** Authentication guidance must stay legible at normal reading size. Never shrink security caveats into fine print.

## 4. Elevation

Vestibule should be flat by default. Depth comes from tonal layering, soft borders, and state changes rather than broad shadows. A security library should not feel floaty or glassy; panels should feel placed, not hovering.

### Shadow Vocabulary
- **Interactive Lift** (`0 6px 12px oklch(0.200 0.035 300 / 0.10)`): Optional hover lift for a primary CTA or provider button on a marketing-adjacent demo surface. Do not combine it with a decorative 1px border unless the border is structural and the blur stays small.

### Named Rules

**The Flat First Rule.** Surfaces are flat at rest. Shadows appear only as a state response, never as the default way to make a card "designed."

## 5. Components

### Buttons
- **Shape:** Crisp, modest rounding (6px). No pill buttons unless the control is a compact chip.
- **Primary:** Filled `brand-purple` with white text, label typography, and 12px 18px padding.
- **Hover / Focus:** Hover shifts to `brand-purple-hover`; focus uses a 3px `threshold-yellow` outline offset by 2px.
- **Secondary / Ghost:** Yellow secondary buttons use `threshold-yellow` with `ink` text. Ghost buttons are text-first with a transparent background and purple hover surface.

### Chips
- **Style:** Provider and state chips use `brand-purple-soft` with `brand-purple` text, 6px radius, and compact 6px 10px padding.
- **State:** Selected chips may add an inset purple border. Do not use yellow chips for routine provider labels; yellow is reserved for important prompts or cautionary setup notes.

### Cards / Containers
- **Corner Style:** Quietly rounded (14px) for panels and example blocks.
- **Background:** Use `surface` on white, or white inside a `surface` page region.
- **Shadow Strategy:** Flat at rest; use borders or tonal contrast before shadows.
- **Border:** 1px `border` for panels that need separation from white.
- **Internal Padding:** 24px for standard panels, 16px for compact examples, 40px for hero-like documentation introductions.

### Inputs / Fields
- **Style:** White fill, 1px `border`, 6px radius, `ink` text, and `muted` placeholder copy.
- **Focus:** Border shifts to `brand-purple`; focus outline uses `threshold-yellow` so keyboard focus is unmistakable.
- **Error / Disabled:** Errors use `danger` text plus an icon or message, never color alone. Disabled states lower opacity only when the label remains readable.

### Navigation
- **Style, typography, default/hover/active states, mobile treatment.** Navigation should be text-first and compact. Active states use `brand-purple`; hover states use `brand-purple-soft`. On narrow screens, collapse into a simple stacked list or native disclosure pattern rather than a custom animated menu.

### Authentication Result Panel

Use a two-column key/value layout for provider, UID, name, email, and nickname. Keys use label typography in `muted`; values use body typography in `ink`. Long provider IDs should wrap, not overflow.

## 6. Do's and Don'ts

### Do:
- **Do** use purple for primary actions, selected states, and brand identity.
- **Do** use yellow sparingly as the checkpoint light for focus, next-step emphasis, and important setup guidance.
- **Do** keep body backgrounds pure white and text high-contrast.
- **Do** make security responsibilities visible near the action they affect.
- **Do** use reduced-motion-safe, 150-200ms transitions for hover, focus, and state changes only.

### Don't:
- **Don't** make Vestibule look like "loud SaaS growth marketing."
- **Don't** use flashy gradients, gimmicky identity-provider spectacle, mascots, over-animation, exaggerated metrics, or generic auth-dashboard theatrics.
- **Don't** turn provider buttons into a rainbow brand grid unless the provider identity itself is the only content.
- **Don't** use yellow as a page background or large decorative block.
- **Don't** pair a 1px border with a large soft shadow on cards or buttons; choose structural border or small state shadow, not both.
- **Don't** use side-stripe borders, gradient text, glassmorphism, or repeated tiny uppercase section eyebrows.
