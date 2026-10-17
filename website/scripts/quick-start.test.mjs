import assert from "node:assert/strict";
import test from "node:test";
import {
  callbackFailureCode,
  coreCode,
  providerSetups,
  registryCode,
  wispCode
} from "../src/data/doc-snippets.ts";

test("each hosted provider supplies the variables used by every route path", () => {
  assert.deepEqual(providerSetups.map(({ id }) => id), [
    "github", "google", "microsoft", "apple"
  ]);
  for (const provider of providerSetups) {
    assert.match(provider.code, new RegExp(`import vestibule_${provider.id}\\b`));
    assert.match(provider.code, /let strategy = /);
    assert.match(provider.code, /let client_config =/);
    assert.match(provider.code, new RegExp(`/auth/${provider.id}/callback`));
    assert.match(provider.code, /auth: config\.client_secret_auth\(/);
    for (const other of providerSetups.filter(({ id }) => id !== provider.id)) {
      assert.doesNotMatch(provider.code, new RegExp(`vestibule_${other.id}\\b`));
    }
  }
  assert.match(registryCode, /registry\.register\(strategy, client_config\)/);
  assert.ok(wispCode.includes(registryCode));
  for (const code of [coreCode, registryCode, wispCode]) {
    assert.doesNotMatch(code, /vestibule_(github|google|microsoft|apple)\b/);
  }
});

test("Apple setup initializes the provider and generates its client-secret JWT", () => {
  const apple = providerSetups.find(({ id }) => id === "apple");
  assert.match(apple.code, /vestibule_apple\.initialize\(\)/);
  assert.match(apple.code, /vestibule_apple\.strategy\(apple\)/);
  assert.match(apple.code, /vestibule_apple\.build_client_secret\(/);
  assert.match(apple.code, /p8_pem: p8_pem/);
  assert.match(apple.code, /config\.client_secret_auth\(client_secret\)/);
  assert.equal(new URL(apple.redirectUri).protocol, "https:");
  assert.notEqual(new URL(apple.redirectUri).hostname, "localhost");
});

test("core callbacks preserve the nonce required by Apple", () => {
  assert.match(coreCode, /authorization_request\.nonce\(auth_request\)/);
  for (const code of [coreCode, callbackFailureCode]) {
    assert.match(code, /expected_nonce: stored_nonce/);
    assert.doesNotMatch(code, /expected_nonce: option\.None/);
  }
});
