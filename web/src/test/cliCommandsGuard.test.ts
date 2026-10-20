/**
 * CLI-example guard for the web UI copy.
 *
 * What it does: parses every non-test source file under web/src with the TypeScript
 * parser and looks at the TEXT of every string literal, no-substitution template,
 * template chunk and JSX text node (comments are not scanned). In that text it fails on
 *   - `keyorix <word>` where <word> is not a real top-level CLI command, and
 *   - the secret-as-flag options `--password`, `--value`, `--mfa-code` and `--url` (a webhook URL)
 *     (secrets on the command line leak into `ps` and shell history; the CLI refuses
 *     them since #3325, so the UI must not teach them).
 *
 * The list of real top-level commands is NOT written by hand: it is derived on every run
 * from the CLI source (cli/cmd/*.go): each `rootCmd.AddCommand(xCmd)` is resolved to the
 * first word of that command's cobra `Use:`. Cobra's built-in `help` and `completion` are
 * added. If the CLI source can no longer be parsed (fewer commands than a sanity floor, or
 * an AddCommand argument that does not resolve to a `Use:`), the test fails instead of
 * silently accepting everything.
 *
 * What it does NOT see:
 *   - commands assembled from variables or concatenation (`'keyor' + 'ix ' + name`,
 *     `${bin} connect`); only the literal text is inspected, so `keyorix` must appear
 *     in the same literal as the subcommand;
 *   - nested subcommands and flags other than the three above (only the first word after
 *     `keyorix` is checked, e.g. `keyorix secret frobnicate` passes);
 *   - copy that does not start with `keyorix` (an alias, `./keyorix`-style paths are seen,
 *     `kx connect` is not);
 *   - commands rendered from data fetched at runtime, and non-TS assets (markdown, JSON);
 *   - the server binary's own subcommands: they are only accepted here if they also
 *     happen to be root commands of the CLI (e.g. `license`).
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const WEB_SRC = path.resolve(__dirname, '..');
const CLI_CMD_DIR = path.resolve(__dirname, '../../../cli/cmd');

const COBRA_BUILTINS = ['help', 'completion'];
const FORBIDDEN_FLAGS = ['--password', '--value', '--mfa-code', '--url'];
const SANITY_FLOOR = 20;

/** Derive the top-level command names from cli/cmd/*.go (never by hand). */
function realTopLevelCommands(): { commands: Set<string>; unresolved: string[] } {
    const files = fs
        .readdirSync(CLI_CMD_DIR)
        .filter((f) => f.endsWith('.go') && !f.endsWith('_test.go'))
        .map((f) => fs.readFileSync(path.join(CLI_CMD_DIR, f), 'utf8'));
    const src = files.join('\n');

    const usesByVar = new Map<string, string>();
    const decl = /\b(\w+)\s*=\s*&cobra\.Command\{[^}]*?\bUse:\s*"([^"\s]+)/gs;
    for (const m of src.matchAll(decl)) usesByVar.set(m[1]!, m[2]!);

    const commands = new Set<string>(COBRA_BUILTINS);
    const unresolved: string[] = [];
    for (const m of src.matchAll(/\brootCmd\.AddCommand\(([^)]*)\)/g)) {
        for (const raw of m[1]!.split(',')) {
            const name = raw.trim();
            if (!name) continue;
            const use = usesByVar.get(name);
            if (use) commands.add(use);
            else unresolved.push(name);
        }
    }
    return { commands, unresolved };
}

function sourceFiles(dir: string, out: string[] = []): string[] {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === 'test' || entry.name === '__tests__' || entry.name === 'node_modules') continue;
            sourceFiles(full, out);
        } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name)) {
            out.push(full);
        }
    }
    return out;
}

interface Literal {
    file: string;
    line: number;
    text: string;
}

/** Text of every string-ish literal in a file; comments are never visited. */
function literalsOf(file: string): Literal[] {
    const code = fs.readFileSync(file, 'utf8');
    const sf = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const found: Literal[] = [];
    const add = (node: ts.Node, text: string) => {
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        found.push({ file: path.relative(WEB_SRC, file), line: line + 1, text });
    };
    const visit = (node: ts.Node) => {
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) add(node, node.text);
        else if (ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) add(node, node.text);
        else if (ts.isJsxText(node)) add(node, node.text);
        ts.forEachChild(node, visit);
    };
    visit(sf);
    return found;
}

describe('web copy teaches only real CLI commands', () => {
    const { commands, unresolved } = realTopLevelCommands();

    it('derives the command list from the CLI source (sanity)', () => {
        expect(unresolved, 'AddCommand arguments with no matching `Use:`').toEqual([]);
        expect(commands.size).toBeGreaterThanOrEqual(SANITY_FLOOR);
        for (const c of ['login', 'secret', 'run']) expect(commands.has(c)).toBe(true);
        expect(commands.has('connect')).toBe(false);
    });

    it('has no unknown `keyorix <subcommand>` and no secret-as-flag options in string literals', () => {
        const problems: string[] = [];
        for (const file of sourceFiles(WEB_SRC)) {
            for (const lit of literalsOf(file)) {
                for (const m of lit.text.matchAll(/(?<![\w/.-])keyorix\s+([a-z][a-z0-9-]*)/g)) {
                    if (!commands.has(m[1]!)) {
                        problems.push(`${lit.file}:${lit.line}: "keyorix ${m[1]}" is not a CLI command`);
                    }
                }
                for (const flag of FORBIDDEN_FLAGS) {
                    if (new RegExp(`(^|\\s)${flag}(?![\\w-])`).test(lit.text)) {
                        problems.push(`${lit.file}:${lit.line}: teaches secret-as-flag ${flag}`);
                    }
                }
            }
        }
        expect(problems).toEqual([]);
    });
});
