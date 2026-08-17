import fsExtra from "fs-extra";
import hcl2jsonWasmPath from "@cdktf/hcl2json/main.wasm.gz" with {
    type: "file",
};

if (Bun.file(hcl2jsonWasmPath).size === 0) {
    throw new Error("The embedded hcl2json WASM asset is empty");
}

const readFile = fsExtra.readFile;
fsExtra.readFile = (path, ...args) => {
    const normalizedPath = String(path).replaceAll("\\", "/");
    if (normalizedPath.endsWith("/@cdktf/hcl2json/main.wasm.gz")) {
        return readFile(hcl2jsonWasmPath, ...args);
    }
    return readFile(path, ...args);
};

await import("../src/index.ts");
