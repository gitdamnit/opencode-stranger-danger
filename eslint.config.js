import tseslint from "typescript-eslint";

/**
 * Deliberately small rule set. This package is security-sensitive, so lint
 * focuses on constructs that can themselves introduce vulnerabilities or hide
 * behavior. Type correctness is enforced separately by `tsc --noEmit`.
 */
export default tseslint.config(
    {
        ignores: ["dist/**", "dist-test/**", "node_modules/**", "src/engine/rules.ts", "src/cli/commands/rules.ts"],
    },
    {
        files: ["**/*.ts"],
        languageOptions: {
            parser: tseslint.parser,
        },
        plugins: {
            "@typescript-eslint": tseslint.plugin,
        },
        rules: {
            "no-debugger": "error",
            "no-eval": "error",
            "no-implied-eval": "error",
            "no-new-func": "error",
        },
    },
);
