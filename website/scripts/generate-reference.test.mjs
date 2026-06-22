import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { generateReference } from "./generate-reference.mjs";

const stringType = { kind: "named", name: "String", package: "", module: "gleam", parameters: [] };
const intType = { kind: "named", name: "Int", package: "", module: "gleam", parameters: [] };
const boolType = { kind: "named", name: "Bool", package: "", module: "gleam", parameters: [] };
const customType = {
  kind: "named",
  name: "External",
  package: "example_pkg",
  module: "example_pkg/external",
  parameters: []
};

async function writeFixture(dir) {
  const docsJsonPath = path.join(dir, "package-interface.json");
  await writeFile(
    docsJsonPath,
    JSON.stringify({
      name: "example_pkg",
      version: "1.2.3",
      modules: {
        "example_pkg/extra": {
          documentation: " Extra module docs.",
          "type-aliases": {},
          types: {},
          constants: {},
          functions: {}
        },
        example_pkg: {
          documentation: [" Example package docs.", "", " More details."],
          "type-aliases": {
            Callback: {
              documentation: " Function alias docs.",
              deprecation: "Use Handler instead.",
              parameters: 1,
              alias: {
                kind: "fn",
                parameters: [
                  { kind: "variable", id: 0 },
                  { kind: "tuple", elements: [stringType, intType] }
                ],
                return: boolType
              }
            }
          },
          types: {
            Box: {
              documentation: " Box docs.",
              deprecation: null,
              parameters: 1,
              constructors: [
                {
                  name: "Box",
                  documentation: " Constructor docs.",
                  parameters: [
                    { label: "value", type: { kind: "variable", id: 0 } },
                    { label: "external", type: customType }
                  ]
                }
              ]
            }
          },
          constants: {
            answer: {
              documentation: " Constant docs.",
              deprecation: null,
              type: intType
            }
          },
          functions: {
            make: {
              documentation: " Make docs.",
              deprecation: { message: "Use create instead." },
              parameters: [
                { label: null, type: stringType },
                {
                  label: "items",
                  type: {
                    kind: "named",
                    name: "List",
                    package: "",
                    module: "gleam",
                    parameters: [stringType]
                  }
                }
              ],
              return: {
                kind: "named",
                name: "Box",
                package: "example_pkg",
                module: "example_pkg",
                parameters: [{ kind: "variable", id: 1 }]
              }
            }
          }
        }
      }
    }),
  );
  return docsJsonPath;
}

test("generates an index and module pages from package-interface.json", async () => {
  const tmp = await mkdtemp(path.join(os.tmpdir(), "gleam-reference-"));
  const outputDir = path.join(tmp, "reference");
  const docsJsonPath = await writeFixture(tmp);

  const result = await generateReference({ docsJsonPath, outputDir, packageName: "example_pkg" });

  assert.equal(result.pageCount, 3);
  assert.equal(result.moduleCount, 2);

  const index = await readFile(path.join(outputDir, "index.md"), "utf8");
  assert.match(index, /title: "Reference"/);
  assert.match(index, /This reference is generated from Gleam's docs metadata for the Vestibule packages: `example_pkg`/);
  assert.match(index, /\| `example_pkg` \| `1\.2\.3` \| 2 \|/);
  assert.match(index, /\| `example_pkg` \| \[`example_pkg`\]\(\/docs\/reference\/example_pkg\) \|/);
  assert.match(index, /\| `example_pkg` \| \[`example_pkg\/extra`\]\(\/docs\/reference\/example_pkg-extra\) \|/);

  const modulePage = await readFile(path.join(outputDir, "example_pkg.md"), "utf8");
  assert.match(modulePage, /nav:\n  group: Reference/);
  assert.match(modulePage, /## Types/);
  assert.match(modulePage, /## Type aliases/);
  assert.match(modulePage, /## Constants/);
  assert.match(modulePage, /## Functions/);
  assert.match(modulePage, /pub type Box\(a\) \{\n  Box\(\n    value: a,\n    external: external\.External\n  \)\n\}/);
  assert.match(modulePage, /pub type Callback\(a\) = fn\(a, #\(String, Int\)\) -> Bool/);
  assert.match(modulePage, /> \*\*Deprecated:\*\* Use Handler instead\./);
  assert.match(modulePage, /pub const answer: Int/);
  assert.match(modulePage, /pub fn make\(\n  String,\n  items: List\(String\)\n\) -> Box\(b\)/);
  assert.match(modulePage, /> \*\*Deprecated:\*\* Use create instead\./);
});

test("missing package-interface.json mentions gleam docs build", async () => {
  const tmp = await mkdtemp(path.join(os.tmpdir(), "gleam-reference-"));
  const outputDir = path.join(tmp, "reference");
  const docsJsonPath = path.join(tmp, "missing-package-interface.json");

  await assert.rejects(
    generateReference({ docsJsonPath, outputDir, packageName: "example_pkg" }),
    /Run `gleam docs build` from the repository root first\./,
  );
});
