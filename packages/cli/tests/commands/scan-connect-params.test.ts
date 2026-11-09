import { describe, expect, test } from "bun:test";
import { applyChamberToConnectParams, buildConnectParams } from "../../src/commands/scan.js";

describe("scan connect parameter mapping", () => {
  test("maps MCP Streamable HTTP URLs to adapter url params", () => {
    expect(buildConnectParams("mcp", "http://127.0.0.1:3100/mcp", "streamable-http")).toEqual({
      url: "http://127.0.0.1:3100/mcp",
      transport: "streamable-http",
    });
  });

  test("maps MCP stdio commands to command args", () => {
    expect(buildConnectParams("mcp", "node server.js --flag", "stdio")).toEqual({
      command: "node",
      args: ["server.js", "--flag"],
      transport: "stdio",
    });
  });

  test("maps live A2A URLs to adapter url params", () => {
    expect(buildConnectParams("a2a", "http://127.0.0.1:4100", "streamable-http")).toEqual({
      url: "http://127.0.0.1:4100",
    });
  });

  test("maps A2A files to adapter specFile params", () => {
    expect(buildConnectParams("a2a", "fixtures/agent-card.json", "stdio")).toEqual({
      specFile: "fixtures/agent-card.json",
    });
  });

  test("injects chamber network flags into docker-run stdio targets", () => {
    const params = buildConnectParams("mcp", "docker run --rm -i scanner-fetch:local", "stdio");
    const patched = applyChamberToConnectParams(params, {
      network: { name: "fetch_chamber_net" },
      services: {
        fakeDns: { host: "172.30.0.53" },
        fakeHttp: { url: "http://172.30.0.10:8080" },
        fakeMetadata: { url: "http://172.30.0.12" },
      },
    } as any);

    expect(patched.command).toBe("docker");
    expect(patched.args).toEqual([
      "run",
      "--network", "fetch_chamber_net",
      "--dns", "172.30.0.53",
      "-e", "SCANNER_CHAMBER_HTTP_URL=http://172.30.0.10:8080",
      "-e", "SCANNER_CHAMBER_METADATA_URL=http://172.30.0.12",
      "-e", "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://172.30.0.12",
      "--rm",
      "-i",
      "scanner-fetch:local",
    ]);
  });
});
