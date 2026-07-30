import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function filesUnder(root: string): string[] {
  return readdirSync(root).flatMap((entry) => {
    const path = join(root, entry);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

describe("frontend source security boundaries", () => {
  it("keeps the delivery environment key out of client modules", () => {
    const clientRoots = [join(process.cwd(), "src", "components"), join(process.cwd(), "src", "lib")];
    const source = clientRoots
      .flatMap(filesUnder)
      .filter((path) => /\.(ts|tsx)$/.test(path) && !path.endsWith(".test.ts") && !path.endsWith(".test.tsx"))
      .map((path) => readFileSync(path, "utf8"))
      .join("\n");
    expect(source).not.toContain("FIREMARK_DELIVERY_API_KEY");
    expect(source).not.toContain("Authorization: `Bearer");
  });

  it("does not persist delivery URLs or write authorization data to logs", () => {
    const source = filesUnder(join(process.cwd(), "src"))
      .filter((path) => /\.(ts|tsx)$/.test(path) && !path.endsWith(".test.ts") && !path.endsWith(".test.tsx"))
      .map((path) => readFileSync(path, "utf8"))
      .join("\n");
    expect(source).not.toMatch(/localStorage|sessionStorage|console\.(log|info|warn|error)/);
  });
});
