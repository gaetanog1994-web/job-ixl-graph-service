import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import neo4j from "neo4j-driver";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const {
  PORT = 8787,
  NEO4J_URI,
  NEO4J_USER,
  NEO4J_PASSWORD,
  GRAPH_SERVICE_TOKEN,
} = process.env;

if (!NEO4J_URI || !NEO4J_USER || !NEO4J_PASSWORD) {
  console.error("❌ Missing Neo4j env vars");
  process.exit(1);
}

if (!GRAPH_SERVICE_TOKEN) {
  console.error("❌ Missing GRAPH_SERVICE_TOKEN");
  process.exit(1);
}

/* ----------------------------------
   Neo4j Driver (singleton)
---------------------------------- */
const driver = neo4j.driver(
  NEO4J_URI,
  neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD)
);

/* ----------------------------------
   Auth middleware
---------------------------------- */
function requireToken(req, res, next) {
  const token = req.header("x-graph-token");
  if (!token || token !== GRAPH_SERVICE_TOKEN) {
    return res.status(401).json({
      status: "ERROR",
      message: "Unauthorized",
    });
  }
  next();
}

/* ----------------------------------
   Health check
---------------------------------- */
app.get("/health", (_req, res) => {
  res.json({ status: "OK" });
});

/* ----------------------------------
   BUILD GRAPH (write / reset)
---------------------------------- */
app.post("/build-graph", requireToken, async (req, res) => {
  const { applications, usersById } = req.body || {};

  if (!Array.isArray(applications)) {
    return res.status(400).json({
      status: "ERROR",
      message: "`applications` must be an array",
    });
  }

  const session = driver.session();

  try {
    // Reset grafo derivato
    await session.run("MATCH (n) DETACH DELETE n");

    // Build nodi + relazioni
    await session.run(
      `
      UNWIND $apps AS app
      MERGE (a:Person {id: app.user_id})
      ON CREATE SET a.full_name = coalesce($usersById[app.user_id], null)
      ON MATCH  SET a.full_name = coalesce($usersById[app.user_id], a.full_name)

      MERGE (b:Person {id: app.target_user_id})
      ON CREATE SET b.full_name = coalesce($usersById[app.target_user_id], null)
      ON MATCH  SET b.full_name = coalesce($usersById[app.target_user_id], b.full_name)

      MERGE (a)-[r:CANDIDATO_A]->(b)
      SET r.priority = app.priority
      `,
      { apps: applications, usersById: usersById || {} }
    );

    const nodesRes = await session.run(
      "MATCH (n:Person) RETURN count(n) AS c"
    );
    const relsRes = await session.run(
      "MATCH (:Person)-[r:CANDIDATO_A]->(:Person) RETURN count(r) AS c"
    );

    const nodes = nodesRes.records[0].get("c").toNumber();
    const relationships = relsRes.records[0].get("c").toNumber();

    res.json({
      status: "OK",
      applications_processed: applications.length,
      nodes,
      relationships,
    });
  } catch (err) {
    console.error("Error in /build-graph:", err);
    res.status(500).json({
      status: "ERROR",
      message: err?.message ?? String(err),
    });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   READ GRAPH (summary)
---------------------------------- */
app.get("/graph/summary", requireToken, async (_req, res) => {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (a:Person)-[r:CANDIDATO_A]->(b:Person)
      RETURN 
        a.id AS from_id,
        a.full_name AS from_name,
        b.id AS to_id,
        b.full_name AS to_name,
        r.priority AS priority
      ORDER BY r.priority ASC
    `);

    const rows = result.records.map((r) => ({
      from_id: r.get("from_id"),
      from_name: r.get("from_name"),
      to_id: r.get("to_id"),
      to_name: r.get("to_name"),
      priority: r.get("priority"),
    }));

    res.json({
      status: "OK",
      relationships: rows,
    });
  } catch (err) {
    console.error("Error in /graph/summary:", err);
    res.status(500).json({
      status: "ERROR",
      message: err?.message ?? String(err),
    });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   FIND CHAINS (interlocking cycles)
---------------------------------- */
app.get("/graph/chains", requireToken, async (_req, res) => {
  const session = driver.session();

  try {
    // MVP: cicli diretti semplici (>=2). Limite max 10 per evitare esplosioni.
    const cypher = `
      MATCH path = (p:Person)-[:CANDIDATO_A*2..10]->(p)
      WHERE all(n IN nodes(path) WHERE single(m IN nodes(path) WHERE m = n))
      RETURN
        [n IN nodes(path) | { id: n.id, name: n.full_name }] AS persons,
        length(path) AS length
      ORDER BY length ASC
    `;

    const result = await session.run(cypher);

    const chains = result.records.map((r) => {
      const persons = r.get("persons");
      const length = r.get("length").toNumber();

      // helper per UI: stringa "A → B → C → A"
      const names = persons.map((p) => p.name ?? p.id);
      const cycle = names.length > 0 ? `${names.join(" → ")} → ${names[0]}` : "";

      return { length, persons, cycle };
    });

    res.json({
      status: "OK",
      chains,
    });
  } catch (err) {
    console.error("Error in /graph/chains:", err);
    res.status(500).json({
      status: "ERROR",
      message: err?.message ?? String(err),
    });
  } finally {
    await session.close();
  }
});

/* ----------------------------------
   START SERVER (always last)
---------------------------------- */
app.listen(Number(PORT), () => {
  console.log(`🚀 Graph service listening on port ${PORT}`);
});

/* ----------------------------------
   Graceful shutdown
---------------------------------- */
async function shutdown(signal) {
  try {
    console.log(`🛑 Received ${signal}, closing Neo4j driver...`);
    await driver.close();
    process.exit(0);
  } catch (e) {
    console.error("Shutdown error:", e);
    process.exit(1);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
