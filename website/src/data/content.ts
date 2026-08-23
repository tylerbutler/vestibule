import { getCollection, type CollectionEntry } from "astro:content";

export type DocsEntry = CollectionEntry<"docs">;
export type PackageEntry = CollectionEntry<"packages">;

export type NavLink = {
  href: string;
  label: string;
};

export type NavGroup = {
  title: string;
  links: NavLink[];
};

export type SearchEntry = {
  title: string;
  href: string;
  category: string;
  description: string;
  terms: string;
  external?: boolean;
};

type NavItem = NavLink & {
  group: string;
  groupOrder: number;
  order: number;
};

const staticNavItems: NavItem[] = [
  {
    group: "Start",
    groupOrder: 0,
    order: 0,
    href: "/",
    label: "Overview"
  },
  {
    group: "Start",
    groupOrder: 0,
    order: 90,
    href: "/docs/search",
    label: "Search docs"
  },
  {
    group: "Packages",
    groupOrder: 10,
    order: 0,
    href: "/docs/packages",
    label: "Package overview"
  }
];

const staticSearchEntries: SearchEntry[] = [
  {
    title: "Overview",
    href: "/",
    category: "Start",
    description: "Open the Vestibule overview page.",
    terms: "start overview oauth gleam vestibule providers packages csrf state pkce sign-in"
  },
  {
    title: "Package overview",
    href: "/docs/packages",
    category: "Packages",
    description: "Choose the right Vestibule package for a Gleam OAuth integration.",
    terms: "packages compare core middleware providers wisp mist github google microsoft apple indieauth oidc openid connect"
  },
  {
    title: "Search docs",
    href: "/docs/search",
    category: "Start",
    description: "Search Vestibule documentation and package guides.",
    terms: "search docs documentation api reference"
  }
];

const stripExtension = (id: string) =>
  id.replace(/\.(md|mdx)$/i, "").replace(/\/index$/i, "");

export const docsSlug = (entry: DocsEntry) => stripExtension(entry.id);

export const docsHref = (entry: DocsEntry) => `/docs/${docsSlug(entry)}`;

export const packageSlug = (entry: PackageEntry) => stripExtension(entry.id);

export const packageHref = (entry: PackageEntry) => `/docs/packages/${packageSlug(entry)}`;

export const packageReferenceUrl = (entry: PackageEntry) =>
  `/docs/reference/${entry.data.name}`;

const sortByNav = (left: DocsEntry, right: DocsEntry) =>
  left.data.nav.groupOrder - right.data.nav.groupOrder ||
  left.data.nav.order - right.data.nav.order ||
  left.data.title.localeCompare(right.data.title);

const sortPackages = (left: PackageEntry, right: PackageEntry) =>
  left.data.navOrder - right.data.navOrder ||
  left.data.name.localeCompare(right.data.name);

export async function getDocsEntries({ includeHidden = false } = {}) {
  const docs = await getCollection("docs", ({ data }) => includeHidden || !data.nav.hidden);
  return docs.sort(sortByNav);
}

export async function getPackageEntries() {
  const packages = await getCollection("packages");
  return packages.sort(sortPackages);
}

export async function getPackageEntry(slug: string) {
  const packages = await getPackageEntries();
  return packages.find((entry) => packageSlug(entry) === slug);
}

export async function getNavigation() {
  const docs = await getDocsEntries();
  const packages = await getPackageEntries();
  const items: NavItem[] = [
    ...staticNavItems,
    ...docs.map((entry) => ({
      group: entry.data.nav.group,
      groupOrder: entry.data.nav.groupOrder,
      order: entry.data.nav.order,
      href: docsHref(entry),
      label: entry.data.nav.label || entry.data.title
    })),
    ...packages.map((entry) => ({
      group: "Packages",
      groupOrder: 10,
      order: entry.data.navOrder,
      href: packageHref(entry),
      label: entry.data.navLabel || entry.data.name
    }))
  ];

  const groups = new Map<string, { order: number; links: Array<NavLink & { order: number }> }>();

  for (const item of items) {
    const group = groups.get(item.group) || { order: item.groupOrder, links: [] };
    group.order = Math.min(group.order, item.groupOrder);
    group.links.push({ href: item.href, label: item.label, order: item.order });
    groups.set(item.group, group);
  }

  return Array.from(groups.entries())
    .sort(([, left], [, right]) => left.order - right.order)
    .map(([title, group]) => ({
      title,
      links: group.links
        .sort((left, right) => left.order - right.order || left.label.localeCompare(right.label))
        .map(({ href, label }) => ({ href, label }))
    }));
}

export async function getSearchEntries() {
  const docs = await getDocsEntries();
  const packages = await getPackageEntries();
  const entries: SearchEntry[] = [
    ...staticSearchEntries,
    ...docs.map((entry) => ({
      title: entry.data.title,
      href: docsHref(entry),
      category: entry.data.nav.group,
      description: entry.data.description,
      terms: [
        entry.data.nav.group,
        entry.data.title,
        entry.data.description,
        ...entry.data.searchTerms
      ].join(" ")
    })),
    ...packages.flatMap((entry) => [
      {
        title: `${entry.data.name} package`,
        href: packageHref(entry),
        category: entry.data.kind,
        description: entry.data.summary,
        terms: [
          entry.data.name,
          entry.data.navLabel || "",
          entry.data.kind,
          entry.data.summary,
          entry.data.useWhen,
          entry.data.defaultScopes || "",
          ...entry.data.setup,
          ...entry.data.highlights,
          ...entry.data.notes,
          ...entry.data.searchTerms
        ].join(" ")
      },
      {
        title: `${entry.data.name} API docs`,
        href: packageReferenceUrl(entry),
        category: "API reference",
        description: `Open the generated API reference for ${entry.data.name}.`,
        terms: `${entry.data.name} generated API reference modules functions types`
      }
    ])
  ];

  return Array.from(new Map(entries.map((entry) => [entry.href, entry])).values());
}
