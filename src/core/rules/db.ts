import type { Rule } from "../types.js";

/**
 * Connection strings. Only the password inside the userinfo section is the
 * secret — the host and database name are usually the whole point of pasting
 * the string to an agent, so we leave them alone.
 */
export const dbRules: Rule[] = [
  {
    id: "db-connection-string",
    provider: "database",
    description: "Database connection string with credentials",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqps?|mssql|clickhouse|mariadb):\/\/[^:@\s/"']{1,64}:([^@\s/"'`]{3,128})@[^\s"'`]+/gi,
    prefilter: ["://"],
    group: 1,
    confidence: "high",
    // `postgres://user:$DB_PASS@host` is a template, not a leak.
    validate: (secret) => !/^\$\{?[A-Z_]+\}?$/.test(secret) && !/^%[A-Z_]+%$/.test(secret),
  },
  {
    id: "jdbc-password",
    provider: "database",
    description: "JDBC connection password",
    regex: /jdbc:[a-z0-9]+:\/\/[^\s;"']+[;?&]password=([^\s;&"']{3,128})/gi,
    prefilter: ["jdbc:"],
    group: 1,
    confidence: "high",
  },
  {
    id: "mongodb-srv-password",
    provider: "mongodb",
    description: "MongoDB Atlas SRV connection password",
    regex: /mongodb\+srv:\/\/[^:@\s]{1,64}:([^@\s]{3,128})@[a-z0-9.-]+\.mongodb\.net/gi,
    prefilter: ["mongodb+srv://"],
    group: 1,
    confidence: "high",
  },
  {
    id: "basic-auth-url",
    provider: "http",
    description: "HTTP URL with basic-auth credentials",
    regex: /\bhttps?:\/\/[^:@\s/"']{1,64}:([^@\s/"'`]{3,128})@[^\s"'`]+/gi,
    prefilter: ["://"],
    group: 1,
    confidence: "medium",
    validate: (secret) => !/^\$\{?[A-Z_]+\}?$/.test(secret),
  },
];
