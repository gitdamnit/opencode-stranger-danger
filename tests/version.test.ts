import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { VERSION } from "../src/shared/version.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

test("runtime VERSION matches package.json version", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert.equal(
        VERSION,
        pkg.version,
        `src/shared/version.ts says ${VERSION} but package.json says ${pkg.version}; update both before releasing`,
    );
});
