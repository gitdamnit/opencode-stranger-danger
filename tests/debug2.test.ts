import { test, describe } from "node:test";
import assert from "node:assert";
import { NAMED_RULES } from "../src/engine/rules.js";

describe("debug", () => {
    test("works", () => {
        assert.strictEqual(NAMED_RULES.length > 0, true);
    });
});