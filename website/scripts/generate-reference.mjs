// Generates Markdown reference pages from Gleam's package-interface.json.

import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const websiteRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(websiteRoot, "..");
const defaultOutputDir = path.join(
	websiteRoot,
	"src",
	"content",
	"docs",
	"reference",
);
const referenceBaseHref = "/docs/reference";

export async function generateReference({
	docsJsonPath,
	outputDir = defaultOutputDir,
	packageName,
} = {}) {
	const packages = docsJsonPath
		? [await readPackageManifest(repoRoot, packageName)]
		: await readPackageManifests();
	const references = [];
	let moduleCount = 0;

	for (const packageMeta of packages) {
		const jsonPath =
			docsJsonPath ??
			path.join(
				packageMeta.root,
				"build",
				"dev",
				"docs",
				packageMeta.name,
				"package-interface.json",
			);
		const packageInterface = await readPackageInterface(jsonPath, packageMeta.name);
		const modules = Object.entries(packageInterface.modules).sort(([left], [right]) =>
			left.localeCompare(right),
		);
		moduleCount += modules.length;
		references.push({ packageMeta, packageInterface, modules, docsJsonPath: jsonPath });
	}

	await rm(outputDir, { force: true, recursive: true });
	await mkdir(outputDir, { recursive: true });
	await writeFile(path.join(outputDir, "index.md"), renderIndex(references));

	let navIndex = 0;
	for (const reference of references) {
		for (const [moduleName, moduleInterface] of reference.modules) {
			await writeFile(
				path.join(outputDir, `${moduleSlug(moduleName)}.md`),
				renderModulePage(moduleName, moduleInterface, navIndex),
			);
			navIndex += 1;
		}
	}

	return {
		pageCount: moduleCount + 1,
		packageCount: references.length,
		moduleCount,
		docsJsonPath: references.map((reference) => reference.docsJsonPath),
		outputDir,
	};
}

async function readPackageManifests() {
	const packagesRoot = path.join(repoRoot, "packages");
	const packageDirectories = await readdir(packagesRoot, { withFileTypes: true });
	const manifests = [await readPackageManifest(repoRoot)];

	for (const directory of packageDirectories) {
		if (directory.isDirectory()) {
			manifests.push(await readPackageManifest(path.join(packagesRoot, directory.name)));
		}
	}

	return manifests.sort((left, right) => {
		if (left.root === repoRoot) {
			return -1;
		}
		if (right.root === repoRoot) {
			return 1;
		}
		return left.name.localeCompare(right.name);
	});
}

async function readPackageManifest(packageRoot, nameOverride) {
	const gleamTomlPath = path.join(packageRoot, "gleam.toml");
	const gleamToml = await readFile(gleamTomlPath, "utf8");
	const name = nameOverride ?? gleamToml.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
	if (!name) {
		throw new Error(`Missing package name in ${path.relative(repoRoot, gleamTomlPath)}`);
	}
	const description = gleamToml.match(/^description\s*=\s*"([^"]+)"/m)?.[1] ?? "";
	return { name, description, root: packageRoot };
}

async function readPackageInterface(docsJsonPath, packageName) {
	let raw;
	try {
		raw = await readFile(docsJsonPath, "utf8");
	} catch (error) {
		if (error && error.code === "ENOENT") {
			throw new Error(
				`Missing ${path.relative(repoRoot, docsJsonPath)}. Run \`gleam docs build\` from the repository root first.`,
			);
		}
		throw error;
	}

	const parsed = JSON.parse(raw);
	if (!parsed || parsed.name !== packageName || !isPlainObject(parsed.modules)) {
		throw new Error(
			`Invalid Gleam package interface JSON at ${path.relative(repoRoot, docsJsonPath)}`,
		);
	}

	return parsed;
}

function isPlainObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function moduleSlug(moduleName) {
	return moduleName.replaceAll("/", "-");
}

function moduleHref(moduleName) {
	return `${referenceBaseHref}/${moduleSlug(moduleName)}`;
}

function descriptionFromDocs(documentation, fallback) {
	const text = normalizeDoc(documentation);
	const firstParagraph = text
		.split(/\n\s*\n/)
		.find((paragraph) => paragraph.trim().length > 0)
		?.replace(/\s*\n\s*/g, " ");
	return firstParagraph || fallback;
}

function normalizeDoc(documentation) {
	const raw = Array.isArray(documentation)
		? documentation.join("\n")
		: typeof documentation === "string"
			? documentation
			: "";

	return raw
		.split("\n")
		.map((line) => line.replace(/^\s/, "").trimEnd())
		.join("\n")
		.trim();
}

function inlineCode(value) {
	return `\`${String(value).replaceAll("`", "\\`")}\``;
}

function yamlString(value) {
	return JSON.stringify(String(value).replaceAll("\n", " "));
}

function variableSymbol(id) {
	if (!Number.isInteger(id) || id < 0) {
		return "a";
	}
	const letters = "abcdefghijklmnopqrstuvwxyz";
	let remaining = id;
	let symbol = "";
	do {
		symbol = letters[remaining % letters.length] + symbol;
		remaining = Math.floor(remaining / letters.length) - 1;
	} while (remaining >= 0);
	return symbol;
}

function renderTypeParameters(parameters) {
	if (Number.isInteger(parameters)) {
		if (parameters <= 0) {
			return "";
		}
		return `(${Array.from({ length: parameters }, (_, i) => variableSymbol(i)).join(", ")})`;
	}
	if (Array.isArray(parameters) && parameters.length > 0) {
		return `(${parameters.map((parameter) => parameter.name || variableSymbol(parameter.id)).join(", ")})`;
	}
	return "";
}

function renderType(type, currentModule) {
	if (!type || typeof type !== "object") {
		return "Unknown";
	}

	switch (type.kind) {
		case "named": {
			let qualifier = "";
			if (type.module && type.module !== "gleam" && type.module !== currentModule) {
				const segments = type.module.split("/");
				qualifier = `${segments[segments.length - 1]}.`;
			}
			const parameters =
				Array.isArray(type.parameters) && type.parameters.length > 0
					? `(${type.parameters.map((parameter) => renderType(parameter, currentModule)).join(", ")})`
					: "";
			return `${qualifier}${type.name}${parameters}`;
		}
		case "fn": {
			const parameters = Array.isArray(type.parameters)
				? type.parameters.map((parameter) => renderType(parameter, currentModule)).join(", ")
				: "";
			return `fn(${parameters}) -> ${renderType(type.return, currentModule)}`;
		}
		case "tuple":
			return `#(${(type.elements || []).map((element) => renderType(element, currentModule)).join(", ")})`;
		case "variable":
			return variableSymbol(type.id ?? 0);
		default:
			return type.name || type.kind || "Unknown";
	}
}

function renderParameter(parameter, currentModule) {
	const label = parameter.label ? `${parameter.label}: ` : "";
	return `${label}${renderType(parameter.type, currentModule)}`;
}

function renderConstructor(constructor, currentModule) {
	const parameters = constructor.parameters || constructor.arguments || [];
	if (parameters.length === 0) {
		return constructor.name;
	}
	if (parameters.length === 1) {
		return `${constructor.name}(${renderParameter(parameters[0], currentModule)})`;
	}
	const rendered = parameters
		.map((parameter) => renderParameter(parameter, currentModule))
		.join(",\n  ");
	return `${constructor.name}(\n  ${rendered}\n)`;
}

function renderFunctionSignature(name, parameters, returnType, currentModule) {
	let renderedParameters;
	if (!Array.isArray(parameters) || parameters.length === 0) {
		renderedParameters = "()";
	} else if (parameters.length === 1) {
		renderedParameters = `(${renderParameter(parameters[0], currentModule)})`;
	} else {
		const params = parameters
			.map((parameter) => renderParameter(parameter, currentModule))
			.join(",\n  ");
		renderedParameters = `(\n  ${params}\n)`;
	}
	return `pub fn ${name}${renderedParameters} -> ${returnType ? renderType(returnType, currentModule) : "Nil"}`;
}

function renderTypeDefinition(name, typeDef, currentModule) {
	const params = renderTypeParameters(typeDef.parameters || 0);
	const constructors = normalizeConstructors(typeDef.constructors);
	if (constructors.length === 0) {
		return `pub type ${name}${params}`;
	}
	const body = constructors
		.map((constructor) => `  ${renderConstructor(constructor, currentModule).replaceAll("\n", "\n  ")}`)
		.join("\n");
	return `pub type ${name}${params} {\n${body}\n}`;
}

function renderAliasDefinition(name, alias, currentModule) {
	const params = renderTypeParameters(alias.parameters || 0);
	return `pub type ${name}${params} = ${renderType(alias.alias ?? alias.type, currentModule)}`;
}

function renderConstantDefinition(name, constant, currentModule) {
	return `pub const ${name}: ${renderType(constant.type, currentModule)}`;
}

function deprecationBlock(deprecation) {
	if (!deprecation) {
		return "";
	}
	const message =
		typeof deprecation === "string"
			? deprecation.trim()
			: typeof deprecation.message === "string"
				? deprecation.message.trim()
				: "";
	const body = message.length > 0 ? message : "This item has been deprecated.";
	return `\n\n> **Deprecated:** ${body}`;
}

function renderIndex(references) {
	const packageRows = references
		.map(({ packageMeta, packageInterface, modules }) => {
			const description = packageMeta.description || `Reference for ${packageInterface.name}.`;
			return `| ${inlineCode(packageInterface.name)} | ${inlineCode(packageInterface.version)} | ${modules.length} | ${description} |`;
		})
		.join("\n");
	const moduleRows = references
		.flatMap(({ packageInterface, modules }) =>
			modules.map(([moduleName, moduleInterface]) => {
				const description = descriptionFromDocs(
					moduleInterface.documentation,
					`Reference for ${moduleName}.`,
				);
				return `| ${inlineCode(packageInterface.name)} | [${inlineCode(moduleName)}](${moduleHref(moduleName)}) | ${description} |`;
			}),
		)
		.join("\n");
	const packageNames = references
		.map(({ packageInterface }) => inlineCode(packageInterface.name))
		.join(", ");

	return `---
title: "Reference"
description: "Generated API reference from Gleam docs metadata for every Vestibule package."
nav:
  group: Reference
  groupOrder: 20
  order: 0
  label: API overview
toc:
  - href: "#packages"
    label: Packages
  - href: "#modules"
    label: Modules
searchTerms:
  - api
  - reference
  - vestibule
---

# Reference

This reference is generated from Gleam's docs metadata for the Vestibule packages: ${packageNames}.

> **Generated content:** Pages under ${inlineCode(referenceBaseHref)} are generated from Gleam's docs metadata and reflect every public type, function, and constant.

Vestibule packages are not published on Hex. Follow the [installation guide](/docs/installation) to add them as Git dependencies with Gleam 1.18 or later.

## Packages

| Package | Version | Modules | Description |
|---|---:|---:|---|
${packageRows}

## Modules

| Package | Module | Description |
|---|---|---|
${moduleRows}
`;
}

function renderModulePage(moduleName, moduleInterface, index) {
	const description = descriptionFromDocs(
		moduleInterface.documentation,
		`Reference for ${moduleName}.`,
	);
	const sections = [
		renderTypes(moduleInterface.types, moduleName),
		renderTypeAliases(moduleInterface["type-aliases"], moduleName),
		renderConstants(moduleInterface.constants, moduleName),
		renderFunctions(moduleInterface.functions, moduleName),
	].filter(Boolean);
	const toc = sections
		.map((section) => section.match(/^## (.+)$/m)?.[1])
		.filter(Boolean)
		.map((heading) => `  - href: "#${heading.toLowerCase().replaceAll(" ", "-")}"\n    label: ${yamlString(heading)}`)
		.join("\n");

	return `---
title: ${yamlString(moduleName)}
description: ${yamlString(description)}
nav:
  group: Reference
  groupOrder: 20
  order: ${index + 10}
  label: ${yamlString(moduleName)}
${toc ? `toc:\n${toc}` : "toc: false"}
searchTerms:
  - api
  - reference
  - module
  - ${moduleName}
---

# ${inlineCode(moduleName)}

${normalizeDoc(moduleInterface.documentation) || description}

${sections.join("\n\n")}
`;
}

function renderConstructorsSection(typeInterface, moduleName) {
	const constructors = normalizeConstructors(typeInterface.constructors).filter(
		(constructor) => normalizeDoc(constructor.documentation).length > 0,
	);
	if (constructors.length === 0) {
		return "";
	}

	const items = constructors
		.map(
			(constructor) =>
				`##### ${inlineCode(renderConstructor(constructor, moduleName))}\n\n${normalizeDoc(constructor.documentation)}`,
		)
		.join("\n\n");
	return `#### Constructors\n\n${items}`;
}

function renderTypes(types, moduleName) {
	const entries = Object.entries(types || {}).sort(([left], [right]) =>
		left.localeCompare(right),
	);
	if (entries.length === 0) {
		return "";
	}

	return [
		"## Types",
		...entries.map(([name, typeInterface]) => {
			const docs = normalizeDoc(typeInterface.documentation);
			const deprecation = deprecationBlock(typeInterface.deprecation);
			const definition = renderTypeDefinition(name, typeInterface, moduleName);
			const constructors = renderConstructorsSection(typeInterface, moduleName);
			const sections = [
				docs ? `${docs}${deprecation}` : deprecation.replace(/^\n\n/, ""),
				`\`\`\`gleam\n${definition}\n\`\`\``,
				constructors,
			].filter((section) => section && section.length > 0);
			return `### ${inlineCode(name)}\n\n${sections.join("\n\n")}`;
		}),
	].join("\n\n");
}

function normalizeConstructors(constructors) {
	if (Array.isArray(constructors)) {
		return constructors;
	}
	return Object.entries(constructors || {})
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([name, constructor]) => ({ name, ...constructor }));
}

function renderTypeAliases(typeAliases, moduleName) {
	const entries = Object.entries(typeAliases || {}).sort(([left], [right]) =>
		left.localeCompare(right),
	);
	if (entries.length === 0) {
		return "";
	}

	return [
		"## Type aliases",
		...entries.map(([name, alias]) => {
			const docs = normalizeDoc(alias.documentation);
			const deprecation = deprecationBlock(alias.deprecation);
			const sections = [
				docs ? `${docs}${deprecation}` : deprecation.replace(/^\n\n/, ""),
				`\`\`\`gleam\n${renderAliasDefinition(name, alias, moduleName)}\n\`\`\``,
			].filter((section) => section && section.length > 0);
			return `### ${inlineCode(name)}\n\n${sections.join("\n\n")}`;
		}),
	].join("\n\n");
}

function renderConstants(constants, moduleName) {
	const entries = Object.entries(constants || {}).sort(([left], [right]) =>
		left.localeCompare(right),
	);
	if (entries.length === 0) {
		return "";
	}

	return [
		"## Constants",
		...entries.map(([name, constant]) => {
			const docs = normalizeDoc(constant.documentation);
			const deprecation = deprecationBlock(constant.deprecation);
			const sections = [
				docs ? `${docs}${deprecation}` : deprecation.replace(/^\n\n/, ""),
				`\`\`\`gleam\n${renderConstantDefinition(name, constant, moduleName)}\n\`\`\``,
			].filter((section) => section && section.length > 0);
			return `### ${inlineCode(name)}\n\n${sections.join("\n\n")}`;
		}),
	].join("\n\n");
}

function renderFunctions(functions, moduleName) {
	const entries = Object.entries(functions || {}).sort(([left], [right]) =>
		left.localeCompare(right),
	);
	if (entries.length === 0) {
		return "";
	}

	return [
		"## Functions",
		...entries.map(([name, functionInterface]) => {
			const docs = normalizeDoc(functionInterface.documentation);
			const deprecation = deprecationBlock(functionInterface.deprecation);
			const signature = renderFunctionSignature(
				name,
				functionInterface.parameters,
				functionInterface.return,
				moduleName,
			);
			const sections = [
				docs ? `${docs}${deprecation}` : deprecation.replace(/^\n\n/, ""),
				`\`\`\`gleam\n${signature}\n\`\`\``,
			].filter((section) => section && section.length > 0);
			return `### ${inlineCode(name)}\n\n${sections.join("\n\n")}`;
		}),
	].join("\n\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	generateReference()
		.then(({ pageCount, packageCount, docsJsonPath, outputDir }) => {
			const docsJsonList = docsJsonPath
				.map((jsonPath) => path.relative(repoRoot, jsonPath))
				.join(", ");
			console.log(
				`Generated ${pageCount} reference pages for ${packageCount} packages from ${docsJsonList} in ${path.relative(repoRoot, outputDir)}`,
			);
		})
		.catch((error) => {
			console.error(error.message);
			process.exit(1);
		});
}
