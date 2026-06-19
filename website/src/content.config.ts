import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { z } from "astro/zod";

const navSchema = z.object({
  group: z.string(),
  groupOrder: z.number().int().nonnegative(),
  order: z.number().int().nonnegative(),
  label: z.string().optional(),
  hidden: z.boolean().default(false)
});

const tocEntrySchema = z.object({
  href: z.string(),
  label: z.string()
});

const docs = defineCollection({
  loader: glob({ base: "./src/content/docs", pattern: "**/*.{md,mdx}" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    nav: navSchema,
    toc: z.union([z.boolean(), z.array(tocEntrySchema)]).default(true),
    searchTerms: z.array(z.string()).default([])
  })
});

const packages = defineCollection({
  loader: glob({ base: "./src/content/packages", pattern: "**/*.{md,mdx}" }),
  schema: z.object({
    name: z.string(),
    navLabel: z.string().optional(),
    kind: z.string(),
    summary: z.string(),
    install: z.array(z.string()).min(1),
    useWhen: z.string(),
    defaultScopes: z.string().optional(),
    setup: z.array(z.string()).min(1),
    highlights: z.array(z.string()).min(1),
    code: z.string(),
    notes: z.array(z.string()).min(1),
    navOrder: z.number().int().nonnegative(),
    searchTerms: z.array(z.string()).default([])
  })
});

export const collections = { docs, packages };
