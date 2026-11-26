import { describe, expect, it } from "vitest";
import { findingsForUpload, folderName, relativeToProject } from "./outboundPath";

describe("folderName", () => {
  it("keeps only the last folder", () => {
    expect(folderName("/Users/alice/clients/acme-shop")).toBe("acme-shop");
    expect(folderName("/Users/alice/acme-shop/")).toBe("acme-shop");
    expect(folderName("C:\\Users\\alice\\acme-shop")).toBe("acme-shop");
    expect(folderName("C:\\")).toBe("");
    expect(folderName("/")).toBe("");
    expect(folderName("")).toBe("");
    expect(folderName(undefined)).toBe("");
  });
});

describe("relativeToProject", () => {
  const root = "/Users/alice/acme-shop";
  it("makes paths inside the project relative", () => {
    expect(relativeToProject(root, root + "/src/a.ts")).toBe("src/a.ts");
    expect(relativeToProject(root, root)).toBe(".");
    expect(relativeToProject("C:\\Users\\alice\\shop", "C:\\Users\\alice\\shop\\src\\a.ts")).toBe("src/a.ts");
  });
  it("reduces other absolute paths to the file name", () => {
    expect(relativeToProject(root, "/Users/alice/acme-shop2/x.ts")).toBe("x.ts");
    expect(relativeToProject("", "/Users/alice/.ssh/id_rsa")).toBe("id_rsa");
  });
  it("leaves relative paths and web addresses alone", () => {
    expect(relativeToProject(root, "src/a.ts")).toBe("src/a.ts");
    expect(relativeToProject(root, "https://shop.example/login")).toBe("https://shop.example/login");
    expect(relativeToProject(root, "")).toBe("");
  });
});

describe("findingsForUpload", () => {
  it("copies findings with relative paths and leaves the input alone", () => {
    const root = "/Users/alice/acme-shop";
    const input = [{ ID: "a", FilePath: root + "/src/a.ts", source_file: root + "/api/h.go" }, { ID: "b" }];
    const out = findingsForUpload(root, input);
    expect(out[0]).toEqual({ ID: "a", FilePath: "src/a.ts", source_file: "api/h.go" });
    expect(out[1]).toEqual({ ID: "b" });
    expect(input[0].FilePath).toBe(root + "/src/a.ts");
    expect(JSON.stringify(out)).not.toContain("alice");
  });
  it("also handles the desktop file field", () => {
    const out = findingsForUpload("/Users/alice/acme-shop", [{ id: "c", file: "/Users/alice/acme-shop/a.go", line: 3 }]);
    expect(out[0]).toEqual({ id: "c", file: "a.go", line: 3 });
  });
});
