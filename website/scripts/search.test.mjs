import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const layout = readFileSync(new URL("../src/layouts/DocsLayout.astro", import.meta.url), "utf8");
const styles = readFileSync(new URL("../src/styles/global.css", import.meta.url), "utf8");
const script = Array.from(layout.matchAll(/<script is:inline>([\s\S]*?)<\/script>/g))
  .map(([, body]) => body)
  .find((body) => body.includes('const dialog = document.querySelector("[data-cmd-palette]")'));
assert.ok(script, "The search dialog script must exist.");

class Element {
  hidden = false;
  dataset = {};
  attributes = new Map();
  listeners = new Map();

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  dispatch(type, event = {}) {
    this.listeners.get(type)?.({ target: this, preventDefault() {}, ...event });
  }

  setAttribute(name, value) {
    this.attributes.set(name, value);
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  scrollIntoView() {}
  focus() {}
}

class Input extends Element {
  value = "";
}

class Dialog extends Element {
  open = false;

  showModal() {
    this.open = true;
  }

  close() {
    this.open = false;
    this.dispatch("close");
  }
}

function searchDialog() {
  const input = new Input();
  const list = new Element();
  const empty = new Element();
  const count = new Element();
  const dialog = new Dialog();
  const document = new Element();
  const navigated = [];
  const items = ["quick start", "callback errors", "google provider", "API reference", "PKCE"]
    .map((text, index) => Object.assign(new Element(), {
      id: `cmd-opt-${index}`,
      dataset: { cmdText: text, cmdHref: `/docs/${index}` }
    }));
  const elements = new Map([
    ["[data-cmd-input]", input],
    ["[data-cmd-results]", list],
    ["[data-cmd-empty]", empty],
    ["[data-cmd-count]", count]
  ]);
  dialog.querySelector = (selector) => elements.get(selector);
  dialog.querySelectorAll = () => items;
  document.querySelector = () => dialog;
  document.querySelectorAll = () => [];
  vm.runInNewContext(script, {
    document,
    HTMLDialogElement: Dialog,
    HTMLInputElement: Input,
    navigator: { platform: "Linux" },
    window: { location: { assign: (href) => navigated.push(href) } }
  });
  document.dispatch("keydown", { key: "k", ctrlKey: true });
  const query = (value) => {
    input.value = value;
    input.dispatch("input");
  };
  return { input, list, empty, count, items, navigated, query };
}

test("hidden search grids do not override the hidden attribute", () => {
  assert.match(styles, /\.cmd-results\[hidden\],\s*\.cmd-result\[hidden\]\s*\{\s*display:\s*none;\s*\}/);
});

test("modal search keeps matching rows, counts and keyboard navigation in agreement", () => {
  const search = searchDialog();
  search.query("  CALLBACK érrors  ");
  assert.deepEqual(search.items.filter((item) => !item.hidden), [search.items[1]]);
  assert.equal(search.count.textContent, "1 result");
  assert.equal(search.empty.hidden, true);
  assert.equal(search.list.hidden, false);
  assert.equal(search.input.getAttribute("aria-activedescendant"), search.items[1].id);
  search.input.dispatch("keydown", { key: "ArrowDown" });
  search.input.dispatch("keydown", { key: "Enter" });
  assert.deepEqual(search.navigated, [search.items[1].dataset.cmdHref]);
  assert.equal(search.input.getAttribute("aria-expanded"), "false");
});

test("modal search recovers from no matches when the query is cleared", () => {
  const search = searchDialog();
  search.query("no-such-page");
  assert.equal(search.items.every((item) => item.hidden), true);
  assert.equal(search.count.textContent, "0 results");
  assert.equal(search.empty.hidden, false);
  assert.equal(search.list.hidden, true);
  assert.equal(search.input.getAttribute("aria-activedescendant"), null);
  search.input.dispatch("keydown", { key: "Enter" });
  assert.deepEqual(search.navigated, []);
  search.query("");
  assert.equal(search.items.every((item) => !item.hidden), true);
  assert.equal(search.count.textContent, "5 results");
  assert.equal(search.empty.hidden, true);
  assert.equal(search.list.hidden, false);
});
