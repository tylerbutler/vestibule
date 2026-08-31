# Product

## Register

product

## Users

Vestibule is for Gleam developers building demos, prototypes, and hackathon projects that need real OAuth2/OIDC sign-in — an actual provider round-trip, not a stubbed login — without hand-rolling provider quirks, callback handling, CSRF state, or PKCE. Primary users include Wisp and Mist developers wiring social login into a demo app, prototype builders who need "real auth" working in an afternoon, and strategy authors experimenting with additional OAuth providers. Vestibule is not for production systems: it has not been audited and must not be considered secure.

## Product Purpose

Vestibule provides demo-ready, strategy-based OAuth2 authentication for Gleam: a small, explicit core API plus provider and middleware packages that turn request/callback flows into normalized authentication results. Success means a developer can get a real provider sign-in flow into a demo quickly, see the library's limits — unaudited, not for production — before writing a line of code, and extend the library without magic, macros, or framework lock-in.

## Brand Personality

Honest, quick, and plainspoken. Vestibule should feel like a sharp prototyping tool that is upfront about what it is: real OAuth flows for demos, with the "not audited, not for production" boundary impossible to miss. The tone is helpful and technically precise without ever implying production-grade assurance — every claim about a security mechanism is a statement of what is implemented, never a promise that it is safe.

## Anti-references

Vestibule should not look or feel like loud SaaS growth marketing, and it must never look like enterprise auth infrastructure selling trust. Avoid flashy gradients, gimmicky identity-provider spectacle, mascots, over-animation, exaggerated metrics, and generic auth-dashboard theatrics. The design must not bury the not-for-production disclaimer behind polish, shrink it into fine print, or let documentation copy drift into assurance language.

## Design Principles

1. Make the boundary unmissable: the "not audited, not for production" disclaimer appears wherever the project presents itself, styled as a first-class element, never fine print.
2. Prefer explicitness over magic: reflect the library's strategy-as-data model with clear structure, transparent examples, and predictable UI affordances.
3. State mechanisms, not assurances: describe what is implemented (PKCE, CSRF state, HTTPS checks) factually, and pair security copy with its unaudited status.
4. Support extension: make custom strategy authoring and provider-specific behavior feel first-class, not advanced edge cases.
5. Reduce integration anxiety: surface setup order, failure states, and callback outcomes in a way that helps developers get a demo working quickly.

## Accessibility & Inclusion

Future UI and documentation surfaces should target WCAG 2.2 AA. Designs must support reduced motion, keyboard navigation, visible focus states, readable contrast for body and placeholder text, and color-blind-safe status communication that never relies on color alone.
