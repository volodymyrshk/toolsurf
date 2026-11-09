import { readFileSync } from "node:fs";
import type {
  ServerCapabilities,
  ToolInfo,
} from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

/**
 * GraphQL adapter.
 *
 * Discovers queries and mutations via the GraphQL introspection query,
 * normalizes each field into a ToolInfo for auditing.
 *
 * Connect params:
 *   - url: GraphQL endpoint URL (will run introspection)
 *   - specFile: path to introspection result JSON (offline mode)
 *   - headers: additional headers (e.g., authorization)
 */

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        kind
        name
        description
        fields(includeDeprecated: true) {
          name
          description
          isDeprecated
          deprecationReason
          args {
            name
            description
            defaultValue
            type {
              ...TypeRef
            }
          }
          type {
            ...TypeRef
          }
        }
        inputFields {
          name
          description
          defaultValue
          type {
            ...TypeRef
          }
        }
        enumValues(includeDeprecated: false) {
          name
        }
      }
    }
  }

  fragment TypeRef on __Type {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
  }
`;

interface GqlType {
  kind: string;
  name: string | null;
  ofType?: GqlType | null;
}

interface GqlArg {
  name: string;
  description?: string;
  defaultValue?: string;
  type: GqlType;
}

interface GqlField {
  name: string;
  description?: string;
  isDeprecated?: boolean;
  args: GqlArg[];
  type: GqlType;
}

interface GqlEnumValue {
  name: string;
}

interface GqlFullType {
  kind: string;
  name: string;
  description?: string;
  fields?: GqlField[];
  inputFields?: GqlArg[];
  enumValues?: GqlEnumValue[];
}

interface IntrospectionResult {
  __schema: {
    queryType?: { name: string } | null;
    mutationType?: { name: string } | null;
    subscriptionType?: { name: string } | null;
    types: GqlFullType[];
  };
}

export class GraphQlAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "graphql";
  readonly displayName = "GraphQL";

  private verbose = false;
  private tools: ToolInfo[] = [];
  private url = "";
  private headers: Record<string, string> = {};
  private schema: IntrospectionResult | null = null;

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;
    this.url = (options.params.url as string) ?? "";
    this.headers = (options.params.headers as Record<string, string>) ?? {};

    const specFile = options.params.specFile as string | undefined;

    if (specFile) {
      this.log(`Loading introspection result from: ${specFile}`);
      const content = readFileSync(specFile, "utf-8");
      const raw = JSON.parse(content);
      this.schema = raw.data ?? raw;
    } else if (this.url) {
      this.log(`Running introspection query against: ${this.url}`);
      this.schema = await this.runIntrospection(options.timeoutMs ?? 30_000);
    } else {
      throw new Error(
        "GraphQL adapter requires an endpoint URL or introspection result file. " +
        "Pass --server <graphql-url> or provide specFile in params."
      );
    }

    const schema = this.schema;
    if (!schema) {
      throw new Error("GraphQL introspection did not return a schema");
    }

    this.tools = this.parseSchema(schema);
    this.log(`Discovered ${this.tools.length} operations`);

    return {
      serverInfo: {
        name: this.url || specFile || "graphql",
        version: "introspection",
      },
      protocolVersion: "GraphQL",
      capabilities: {
        queries: true,
        mutations: !!schema.__schema.mutationType,
        subscriptions: !!schema.__schema.subscriptionType,
      },
      tools: this.tools,
      resources: [],
      prompts: [],
      protocol: "graphql",
    };
  }

  async invoke(name: string, args: Record<string, unknown>): Promise<unknown> {
    if (!this.url) {
      throw new Error("Cannot invoke without a GraphQL endpoint URL");
    }

    const tool = this.tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Unknown operation: ${name}`);

    const opType = tool.httpMethod === "MUTATION" ? "mutation" : "query";
    const fieldName = name.replace(/^(query_|mutation_)/, "");

    // Build a parameterised GraphQL operation using variables so that
    // argument values are never interpolated into the query document.
    const argEntries = Object.entries(args);
    let query: string;
    let variables: Record<string, unknown> | undefined;

    if (argEntries.length > 0) {
      const varDefs = argEntries.map((_, i) => `$var${i}: String`).join(", ");
      const argList = argEntries.map(([k], i) => `${k}: $var${i}`).join(", ");
      variables = Object.fromEntries(
        argEntries.map(([, v], i) => [`var${i}`, v])
      );
      query = `${opType} (${varDefs}) { ${fieldName}(${argList}) }`;
    } else {
      query = `${opType} { ${fieldName} }`;
    }

    this.log(`Executing: ${query}`);

    const resp = await fetch(this.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...this.headers,
      },
      body: JSON.stringify({ query, ...(variables ? { variables } : {}) }),
      signal: AbortSignal.timeout(15_000),
    });

    // SECURITY: Classify HTTP status codes for active fuzzing
    const isServerError = resp.status >= 500 && resp.status < 600;
    const isClientError = resp.status >= 400 && resp.status < 500;

    if (isServerError) {
      const bodyText = await resp.text();
      return {
        status: resp.status,
        body: bodyText,
        classification: "SERVER_ERROR",
        fuzzingNote: `GraphQL server crashed (${resp.status}) on fuzzed query — potential vulnerability`,
      };
    }

    if (isClientError) {
      const bodyText = await resp.text();
      return {
        status: resp.status,
        body: bodyText,
        classification: "BLOCKED",
        fuzzingNote: `GraphQL request blocked (${resp.status}) — server rejected malformed query`,
      };
    }

    return await resp.json();
  }

  async disconnect(): Promise<void> {
    this.tools = [];
    this.schema = null;
  }

  private async runIntrospection(timeoutMs: number): Promise<IntrospectionResult> {
    const resp = await fetch(this.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...this.headers,
      },
      body: JSON.stringify({ query: INTROSPECTION_QUERY }),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!resp.ok) {
      throw new Error(`Introspection query failed: ${resp.status} ${resp.statusText}`);
    }

    // HARDENING: Detect HTML responses (e.g., Juice Shop returns HTML at /graphql)
    const contentType = resp.headers.get("content-type") ?? "";
    if (contentType.includes("text/html")) {
      throw new Error(
        `GraphQL endpoint returned HTML instead of JSON (content-type: ${contentType}). ` +
        `The server may not support GraphQL at this URL or may be redirecting to a web page.`,
      );
    }

    const result = (await resp.json()) as { data?: IntrospectionResult; errors?: unknown[] };

    if (result.errors) {
      throw new Error(
        `Introspection returned errors: ${JSON.stringify(result.errors)}`
      );
    }

    if (!result.data?.__schema) {
      throw new Error(
        "Introspection did not return a valid schema. " +
        "The server may have introspection disabled."
      );
    }

    return result.data;
  }

  private parseSchema(schema: IntrospectionResult): ToolInfo[] {
    const tools: ToolInfo[] = [];
    const typeMap = new Map<string, GqlFullType>();

    for (const type of schema.__schema.types) {
      typeMap.set(type.name, type);
    }

    // Process query type
    if (schema.__schema.queryType?.name) {
      const queryType = typeMap.get(schema.__schema.queryType.name);
      if (queryType?.fields) {
        for (const field of queryType.fields) {
          if (field.name.startsWith("__")) continue; // skip introspection fields
          tools.push(this.fieldToTool(field, "query", typeMap));
        }
      }
    }

    // Process mutation type
    if (schema.__schema.mutationType?.name) {
      const mutationType = typeMap.get(schema.__schema.mutationType.name);
      if (mutationType?.fields) {
        for (const field of mutationType.fields) {
          tools.push(this.fieldToTool(field, "mutation", typeMap));
        }
      }
    }

    return tools;
  }

  private fieldToTool(
    field: GqlField,
    opType: "query" | "mutation",
    typeMap: Map<string, GqlFullType>,
  ): ToolInfo {
    const properties: Record<string, unknown> = {};
    const required: string[] = [];

    for (const arg of field.args) {
      const { schema: argSchema, isRequired } = this.gqlTypeToJsonSchema(arg.type, typeMap);
      properties[arg.name] = {
        ...argSchema,
        ...(arg.description ? { description: arg.description } : {}),
        ...(arg.defaultValue ? { default: arg.defaultValue } : {}),
      };
      if (isRequired) required.push(arg.name);
    }

    return {
      name: `${opType}_${field.name}`,
      description: field.description ?? `GraphQL ${opType}: ${field.name}`,
      inputSchema: {
        type: "object",
        properties,
        ...(required.length > 0 ? { required } : {}),
      },
      sourceProtocol: "graphql",
      nativeType: opType,
      httpMethod: opType.toUpperCase(),
      endpointPath: this.url,
    };
  }

  private gqlTypeToJsonSchema(
    type: GqlType,
    typeMap: Map<string, GqlFullType>,
  ): { schema: Record<string, unknown>; isRequired: boolean } {
    // Unwrap NON_NULL
    if (type.kind === "NON_NULL" && type.ofType) {
      const inner = this.gqlTypeToJsonSchema(type.ofType, typeMap);
      return { schema: inner.schema, isRequired: true };
    }

    // LIST
    if (type.kind === "LIST" && type.ofType) {
      const inner = this.gqlTypeToJsonSchema(type.ofType, typeMap);
      return {
        schema: { type: "array", items: inner.schema },
        isRequired: false,
      };
    }

    // SCALAR
    if (type.kind === "SCALAR") {
      return {
        schema: { type: this.scalarToJsonType(type.name ?? "String") },
        isRequired: false,
      };
    }

    // ENUM
    if (type.kind === "ENUM" && type.name) {
      const enumType = typeMap.get(type.name);
      if (enumType?.enumValues && enumType.enumValues.length > 0) {
        return {
          schema: { type: "string", enum: enumType.enumValues.map((v) => v.name) },
          isRequired: false,
        };
      }
      return {
        schema: { type: "string", description: `Enum: ${type.name}` },
        isRequired: false,
      };
    }

    // INPUT_OBJECT
    if (type.kind === "INPUT_OBJECT" && type.name) {
      const inputType = typeMap.get(type.name);
      if (inputType?.inputFields) {
        const props: Record<string, unknown> = {};
        const req: string[] = [];
        for (const field of inputType.inputFields) {
          const { schema, isRequired } = this.gqlTypeToJsonSchema(field.type, typeMap);
          props[field.name] = {
            ...schema,
            ...(field.description ? { description: field.description } : {}),
          };
          if (isRequired) req.push(field.name);
        }
        return {
          schema: {
            type: "object",
            properties: props,
            ...(req.length > 0 ? { required: req } : {}),
          },
          isRequired: false,
        };
      }
    }

    // Fallback
    return { schema: { type: "string" }, isRequired: false };
  }

  private scalarToJsonType(gqlScalar: string): string {
    switch (gqlScalar) {
      case "Int":
        return "integer";
      case "Float":
        return "number";
      case "Boolean":
        return "boolean";
      case "String":
      case "ID":
      default:
        return "string";
    }
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:graphql] ${message}`);
    }
  }
}
