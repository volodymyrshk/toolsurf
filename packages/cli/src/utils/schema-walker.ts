/**
 * Recursive JSON Schema walker.
 *
 * Tool input schemas often contain nested objects, arrays, $ref pointers,
 * and composition keywords (oneOf/anyOf/allOf). Shallow property access
 * misses constraints (or lack thereof) buried in these structures.
 *
 * This walker traverses the full schema tree and invokes a visitor callback
 * at every node, providing the path, depth, and parent context. Modules use
 * it to find unconstrained parameters, injection surfaces, and suspicious
 * defaults at any nesting depth.
 *
 * Handles:
 *   - properties / patternProperties
 *   - items (array items — object or tuple)
 *   - additionalProperties (when it's a schema object)
 *   - oneOf / anyOf / allOf / not
 *   - $ref (inline definitions via $defs / definitions)
 *   - Circular $ref detection (bail after MAX_DEPTH)
 */

/** Maximum recursion depth to prevent infinite loops on circular schemas. */
const MAX_DEPTH = 20;

/** A single node visited during schema traversal. */
export interface SchemaNode {
  /** The sub-schema at this node */
  schema: Record<string, unknown>;
  /** JSON Pointer-style path (e.g., "properties.config.properties.url") */
  path: string;
  /** Property name at this level (leaf segment of path), or "" for root */
  name: string;
  /** Nesting depth (root = 0) */
  depth: number;
  /** Whether this node is inside a composition keyword (oneOf/anyOf/allOf) */
  inComposition: boolean;
  /** The parent schema, if any */
  parent?: Record<string, unknown>;
}

/**
 * Visitor function invoked for each schema node.
 * Return `false` to skip traversing children of this node.
 */
export type SchemaVisitor = (node: SchemaNode) => void | boolean | undefined;

/**
 * Walk a JSON Schema tree recursively, invoking `visitor` at every node.
 */
export function walkSchema(
  schema: unknown,
  visitor: SchemaVisitor,
  options?: { definitions?: Record<string, unknown> }
): void {
  if (!schema || typeof schema !== "object") return;
  const root = schema as Record<string, unknown>;

  // Collect definitions for $ref resolution
  const defs: Record<string, unknown> = {
    ...(options?.definitions ?? {}),
    ...((root.$defs as Record<string, unknown>) ?? {}),
    ...((root.definitions as Record<string, unknown>) ?? {}),
  };

  walkNode(root, "", "", 0, false, undefined, visitor, defs, new Set());
}

function walkNode(
  schema: Record<string, unknown>,
  path: string,
  name: string,
  depth: number,
  inComposition: boolean,
  parent: Record<string, unknown> | undefined,
  visitor: SchemaVisitor,
  definitions: Record<string, unknown>,
  seen: Set<string>,
): void {
  if (depth > MAX_DEPTH) return;

  // Resolve $ref
  if (typeof schema.$ref === "string") {
    const resolved = resolveRef(schema.$ref, definitions);
    if (!resolved) return;
    // Circular detection
    if (seen.has(schema.$ref)) return;
    seen = new Set(seen);
    seen.add(schema.$ref);
    walkNode(resolved, path, name, depth, inComposition, parent, visitor, definitions, seen);
    return;
  }

  // Visit this node
  const result = visitor({ schema, path, name, depth, inComposition, parent });
  if (result === false) return; // skip children

  // Traverse properties
  const properties = schema.properties as Record<string, unknown> | undefined;
  if (properties && typeof properties === "object") {
    for (const [propName, propSchema] of Object.entries(properties)) {
      if (propSchema && typeof propSchema === "object") {
        walkNode(
          propSchema as Record<string, unknown>,
          path ? `${path}.properties.${propName}` : `properties.${propName}`,
          propName,
          depth + 1,
          inComposition,
          schema,
          visitor,
          definitions,
          seen,
        );
      }
    }
  }

  // Traverse patternProperties
  const patternProperties = schema.patternProperties as Record<string, unknown> | undefined;
  if (patternProperties && typeof patternProperties === "object") {
    for (const [pattern, propSchema] of Object.entries(patternProperties)) {
      if (propSchema && typeof propSchema === "object") {
        walkNode(
          propSchema as Record<string, unknown>,
          path ? `${path}.patternProperties.${pattern}` : `patternProperties.${pattern}`,
          `[${pattern}]`,
          depth + 1,
          inComposition,
          schema,
          visitor,
          definitions,
          seen,
        );
      }
    }
  }

  // Traverse items (array)
  if (schema.items) {
    if (Array.isArray(schema.items)) {
      // Tuple validation
      for (let i = 0; i < schema.items.length; i++) {
        const item = schema.items[i];
        if (item && typeof item === "object") {
          walkNode(
            item as Record<string, unknown>,
            path ? `${path}.items[${i}]` : `items[${i}]`,
            `[${i}]`,
            depth + 1,
            inComposition,
            schema,
            visitor,
            definitions,
            seen,
          );
        }
      }
    } else if (typeof schema.items === "object") {
      walkNode(
        schema.items as Record<string, unknown>,
        path ? `${path}.items` : "items",
        "[]",
        depth + 1,
        inComposition,
        schema,
        visitor,
        definitions,
        seen,
      );
    }
  }

  // Traverse additionalProperties (when it's a schema)
  if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
    walkNode(
      schema.additionalProperties as Record<string, unknown>,
      path ? `${path}.additionalProperties` : "additionalProperties",
      "[*]",
      depth + 1,
      inComposition,
      schema,
      visitor,
      definitions,
      seen,
    );
  }

  // Traverse composition keywords
  for (const keyword of ["oneOf", "anyOf", "allOf"] as const) {
    const branches = schema[keyword] as unknown[] | undefined;
    if (Array.isArray(branches)) {
      for (let i = 0; i < branches.length; i++) {
        const branch = branches[i];
        if (branch && typeof branch === "object") {
          walkNode(
            branch as Record<string, unknown>,
            path ? `${path}.${keyword}[${i}]` : `${keyword}[${i}]`,
            name,
            depth + 1,
            true,
            schema,
            visitor,
            definitions,
            seen,
          );
        }
      }
    }
  }

  // Traverse "not"
  if (schema.not && typeof schema.not === "object") {
    walkNode(
      schema.not as Record<string, unknown>,
      path ? `${path}.not` : "not",
      name,
      depth + 1,
      true,
      schema,
      visitor,
      definitions,
      seen,
    );
  }
}

/**
 * Resolve a $ref string against local definitions.
 * Supports "#/$defs/Foo", "#/definitions/Foo", and plain "Foo".
 */
function resolveRef(
  ref: string,
  definitions: Record<string, unknown>,
): Record<string, unknown> | null {
  // "#/$defs/Foo" or "#/definitions/Foo"
  const match = ref.match(/^#\/(?:\$defs|definitions)\/(.+)$/);
  if (match) {
    const name = match[1];
    const resolved = definitions[name];
    if (resolved && typeof resolved === "object") {
      return resolved as Record<string, unknown>;
    }
  }

  // Plain name fallback
  const plain = definitions[ref];
  if (plain && typeof plain === "object") {
    return plain as Record<string, unknown>;
  }

  return null;
}

// ─── Convenience helpers for modules ────────────────────────────────────────

/**
 * Collect all leaf property nodes from a schema (properties at any depth).
 * Useful for finding every parameter that could receive user input.
 */
export interface PropertyInfo {
  name: string;
  path: string;
  schema: Record<string, unknown>;
  depth: number;
  parent?: Record<string, unknown>;
}

export function collectAllProperties(inputSchema: unknown): PropertyInfo[] {
  const results: PropertyInfo[] = [];
  walkSchema(inputSchema, (node) => {
    // Only collect actual property entries (depth > 0 and has a real name)
    if (node.depth > 0 && node.name && !node.name.startsWith("[")) {
      results.push({
        name: node.name,
        path: node.path,
        schema: node.schema,
        depth: node.depth,
        parent: node.parent,
      });
    }
  });
  return results;
}

/**
 * Check if a schema (at any depth) has unconstrained string parameters.
 * Returns an array of property paths that are string-typed with no
 * enum, pattern, or maxLength constraint.
 */
export function findUnconstrainedStrings(inputSchema: unknown): PropertyInfo[] {
  const results: PropertyInfo[] = [];
  walkSchema(inputSchema, (node) => {
    if (
      node.depth > 0 &&
      node.name &&
      !node.name.startsWith("[") &&
      node.schema.type === "string" &&
      !node.schema.enum &&
      !node.schema.pattern &&
      !node.schema.maxLength &&
      !node.schema.const
    ) {
      results.push({
        name: node.name,
        path: node.path,
        schema: node.schema,
        depth: node.depth,
        parent: node.parent,
      });
    }
  });
  return results;
}

/**
 * Check if a schema has any unconstrained nested objects (objects without
 * explicit properties and without additionalProperties: false).
 */
export function findUnconstrainedObjects(inputSchema: unknown): PropertyInfo[] {
  const results: PropertyInfo[] = [];
  walkSchema(inputSchema, (node) => {
    if (
      node.depth > 0 &&
      node.schema.type === "object" &&
      !node.schema.properties &&
      node.schema.additionalProperties !== false
    ) {
      results.push({
        name: node.name,
        path: node.path,
        schema: node.schema,
        depth: node.depth,
        parent: node.parent,
      });
    }
  });
  return results;
}

/**
 * Check if a schema has any unconstrained arrays (arrays without items
 * type constraint or without maxItems).
 */
export function findUnconstrainedArrays(inputSchema: unknown): PropertyInfo[] {
  const results: PropertyInfo[] = [];
  walkSchema(inputSchema, (node) => {
    if (
      node.depth > 0 &&
      node.schema.type === "array" &&
      (!node.schema.items || !node.schema.maxItems)
    ) {
      results.push({
        name: node.name,
        path: node.path,
        schema: node.schema,
        depth: node.depth,
        parent: node.parent,
      });
    }
  });
  return results;
}

/**
 * Collect all default values from a schema at any depth.
 */
export interface DefaultValueInfo {
  name: string;
  path: string;
  defaultValue: unknown;
  schema: Record<string, unknown>;
}

export function collectAllDefaults(inputSchema: unknown): DefaultValueInfo[] {
  const results: DefaultValueInfo[] = [];
  walkSchema(inputSchema, (node) => {
    if (node.depth > 0 && node.schema.default !== undefined) {
      results.push({
        name: node.name,
        path: node.path,
        defaultValue: node.schema.default,
        schema: node.schema,
      });
    }
  });
  return results;
}

/**
 * Collect all description strings from a schema at any depth.
 */
export interface DescriptionInfo {
  name: string;
  path: string;
  description: string;
}

export function collectAllDescriptions(inputSchema: unknown): DescriptionInfo[] {
  const results: DescriptionInfo[] = [];
  walkSchema(inputSchema, (node) => {
    if (node.depth > 0 && typeof node.schema.description === "string" && node.schema.description.length > 0) {
      results.push({
        name: node.name,
        path: node.path,
        description: node.schema.description,
      });
    }
  });
  return results;
}
