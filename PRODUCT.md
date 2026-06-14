# Product

## Register

product

## Users

Vestibule is for Gleam developers building server-side web applications that need OAuth2/OIDC sign-in without hand-rolling provider quirks, callback handling, CSRF state, or PKCE. Primary users include Wisp and Mist app developers adding social login, SaaS builders supporting multiple identity providers, and strategy authors publishing integrations for additional OAuth providers.

## Product Purpose

Vestibule provides strategy-based OAuth2 authentication for Gleam: a small, explicit core API plus provider and middleware packages that turn request/callback flows into normalized authentication results. Success means a developer can add a trusted provider sign-in flow quickly, understand the security responsibilities clearly, and extend the library without magic, macros, or framework lock-in.

## Brand Personality

Secure, calm, and precise. Vestibule should feel like reliable authentication infrastructure: measured, plainspoken, technically serious, and helpful without being cold. The tone should make developers trust the defaults while still seeing exactly where application responsibilities begin.

## Anti-references

Vestibule should not look or feel like loud SaaS growth marketing. Avoid flashy gradients, gimmicky identity-provider spectacle, mascots, over-animation, exaggerated metrics, and generic auth-dashboard theatrics. The design should not obscure security details behind polish or turn documentation into a sales page.

## Design Principles

1. Make the secure path obvious: present state, PKCE, redirect URI, cookie, and token-handling responsibilities at the point where developers need them.
2. Prefer explicitness over magic: reflect the library's strategy-as-data model with clear structure, transparent examples, and predictable UI affordances.
3. Keep trust quiet: use restraint, hierarchy, and precise copy instead of decoration to communicate maturity.
4. Support extension: make custom strategy authoring and provider-specific behavior feel first-class, not advanced edge cases.
5. Reduce integration anxiety: surface setup order, failure states, and callback outcomes in a way that helps developers recover quickly.

## Accessibility & Inclusion

Future UI and documentation surfaces should target WCAG 2.2 AA. Designs must support reduced motion, keyboard navigation, visible focus states, readable contrast for body and placeholder text, and color-blind-safe status communication that never relies on color alone.
