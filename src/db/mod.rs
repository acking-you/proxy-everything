use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use snafu::{ResultExt, Snafu};
use turso::{Builder, Connection, Database, Value as TursoValue, params_from_iter};

#[derive(Debug, Snafu)]
pub enum DbError {
    #[snafu(display("Database build error: {source}"))]
    Build { source: turso::Error },
    #[snafu(display("Database connection error: {source}"))]
    Connect { source: turso::Error },
    #[snafu(display("Database query error: {source}"))]
    Query { source: turso::Error },
    #[snafu(display("Database fs error: {source}"))]
    Fs { source: std::io::Error },
}

pub type Result<T> = std::result::Result<T, DbError>;

#[derive(Debug)]
pub struct Db {
    db: Database,
}

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub ip: String,
    pub dest_host: String,
    pub dest_port: u16,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub duration_ms: i64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub addr: String,
    pub created_at_ms: i64,
    pub last_seen_ms: i64,
    pub is_self: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DbValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RowData {
    pub columns: BTreeMap<String, DbValue>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecResult {
    pub rows: Option<Vec<RowData>>,
    pub affected: u64,
}

impl DbValue {
    fn to_turso_value(&self) -> TursoValue {
        match self {
            DbValue::Null => TursoValue::Null,
            DbValue::Integer(v) => TursoValue::Integer(*v),
            DbValue::Real(v) => TursoValue::Real(*v),
            DbValue::Text(v) => TursoValue::Text(v.clone()),
            DbValue::Blob(v) => TursoValue::Blob(v.clone()),
        }
    }

    fn from_turso_value(value: TursoValue) -> DbValue {
        match value {
            TursoValue::Null => DbValue::Null,
            TursoValue::Integer(v) => DbValue::Integer(v),
            TursoValue::Real(v) => DbValue::Real(v),
            TursoValue::Text(v) => DbValue::Text(v),
            TursoValue::Blob(v) => DbValue::Blob(v),
        }
    }
}

impl Db {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        // Ensure the parent directory exists so the embedded database file can be created.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context(FsSnafu)?;
        }
        // Turso expects a UTF-8 path string; fall back to lossy conversion when needed.
        let path_str = path.to_string_lossy().to_string();
        // Use Turso's embedded builder for a local, SQLite-compatible database file.
        let db = Builder::new_local(&path_str)
            .build()
            .await
            .context(BuildSnafu)?;
        let this = Self { db };
        // Initialize schema in an idempotent way so startups are safe to repeat.
        this.init_schema().await?;
        Ok(this)
    }

    pub async fn open_with_path(path: &str) -> Result<Self> {
        Self::open(Path::new(path)).await
    }

    pub fn connection(&self) -> Result<Connection> {
        self.db.connect().context(ConnectSnafu)
    }

    async fn init_schema(&self) -> Result<()> {
        let conn = self.connection()?;
        // WAL improves concurrent read/write performance for our append-heavy workload.
        conn.execute("PRAGMA journal_mode=WAL;", ())
            .await
            .context(QuerySnafu)?;
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                dest_host TEXT NOT NULL,
                dest_port INTEGER NOT NULL,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL,
                bytes_up INTEGER NOT NULL,
                bytes_down INTEGER NOT NULL,
                latency_ms INTEGER,
                error TEXT
            );
            "#,
            (),
        )
        .await
        .context(QuerySnafu)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(ip);",
            (),
        )
        .await
        .context(QuerySnafu)?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_connections_host ON connections(dest_host);",
            (),
        )
        .await
        .context(QuerySnafu)?;
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS ip_stats (
                ip TEXT PRIMARY KEY,
                total_connections INTEGER NOT NULL,
                total_bytes_up INTEGER NOT NULL,
                total_bytes_down INTEGER NOT NULL,
                avg_latency_ms REAL,
                last_seen_ms INTEGER NOT NULL
            );
            "#,
            (),
        )
        .await
        .context(QuerySnafu)?;
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS ip_sites (
                ip TEXT NOT NULL,
                host TEXT NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                total_connections INTEGER NOT NULL,
                total_bytes_up INTEGER NOT NULL,
                total_bytes_down INTEGER NOT NULL,
                avg_latency_ms REAL,
                PRIMARY KEY (ip, host)
            );
            "#,
            (),
        )
        .await
        .context(QuerySnafu)?;
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                addr TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                last_seen_ms INTEGER NOT NULL,
                is_self INTEGER NOT NULL DEFAULT 0
            );
            "#,
            (),
        )
        .await
        .context(QuerySnafu)?;
        Ok(())
    }

    pub async fn record_connection(&self, record: ConnectionRecord) -> Result<()> {
        let conn = self.connection()?;
        // Persist raw connection details for audit/debug analysis.
        conn.execute(
            r#"
            INSERT INTO connections (
                ip,
                dest_host,
                dest_port,
                started_at_ms,
                ended_at_ms,
                duration_ms,
                bytes_up,
                bytes_down,
                latency_ms,
                error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);
            "#,
            turso::params![
                record.ip.as_str(),
                record.dest_host.as_str(),
                record.dest_port as i64,
                record.started_at_ms,
                record.ended_at_ms,
                record.duration_ms,
                record.bytes_up as i64,
                record.bytes_down as i64,
                record.latency_ms.map(|v| v as i64),
                record.error.as_deref(),
            ],
        )
        .await
        .context(QuerySnafu)?;

        let latency_for_avg = record.latency_ms.map(|v| v as f64);
        // Maintain an IP-level aggregate view so dashboards can query quickly.
        conn.execute(
            r#"
            INSERT INTO ip_stats (
                ip,
                total_connections,
                total_bytes_up,
                total_bytes_down,
                avg_latency_ms,
                last_seen_ms
            ) VALUES (?1, 1, ?2, ?3, ?4, ?5)
            ON CONFLICT(ip) DO UPDATE SET
                total_connections = ip_stats.total_connections + 1,
                total_bytes_up = ip_stats.total_bytes_up + excluded.total_bytes_up,
                total_bytes_down = ip_stats.total_bytes_down + excluded.total_bytes_down,
                avg_latency_ms = CASE
                    WHEN excluded.avg_latency_ms IS NULL THEN ip_stats.avg_latency_ms
                    WHEN ip_stats.avg_latency_ms IS NULL THEN excluded.avg_latency_ms
                    ELSE (ip_stats.avg_latency_ms * ip_stats.total_connections + excluded.avg_latency_ms)
                        / (ip_stats.total_connections + 1)
                END,
                last_seen_ms = excluded.last_seen_ms;
            "#,
            turso::params![
                record.ip.as_str(),
                record.bytes_up as i64,
                record.bytes_down as i64,
                latency_for_avg,
                record.ended_at_ms,
            ],
        )
        .await
        .context(QuerySnafu)?;

        // Track which sites each IP has accessed (with aggregate traffic/latency).
        conn.execute(
            r#"
            INSERT INTO ip_sites (
                ip,
                host,
                first_seen_ms,
                last_seen_ms,
                total_connections,
                total_bytes_up,
                total_bytes_down,
                avg_latency_ms
            ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)
            ON CONFLICT(ip, host) DO UPDATE SET
                last_seen_ms = excluded.last_seen_ms,
                total_connections = ip_sites.total_connections + 1,
                total_bytes_up = ip_sites.total_bytes_up + excluded.total_bytes_up,
                total_bytes_down = ip_sites.total_bytes_down + excluded.total_bytes_down,
                avg_latency_ms = CASE
                    WHEN excluded.avg_latency_ms IS NULL THEN ip_sites.avg_latency_ms
                    WHEN ip_sites.avg_latency_ms IS NULL THEN excluded.avg_latency_ms
                    ELSE (ip_sites.avg_latency_ms * ip_sites.total_connections + excluded.avg_latency_ms)
                        / (ip_sites.total_connections + 1)
                END;
            "#,
            turso::params![
                record.ip.as_str(),
                record.dest_host.as_str(),
                record.started_at_ms,
                record.ended_at_ms,
                record.bytes_up as i64,
                record.bytes_down as i64,
                latency_for_avg,
            ],
        )
        .await
        .context(QuerySnafu)?;

        Ok(())
    }

    pub async fn exec_sql(&self, sql: &str, params: Vec<DbValue>) -> Result<ExecResult> {
        let conn = self.connection()?;
        let sql_trim = sql.trim_start().to_ascii_uppercase();
        let is_query = sql_trim.starts_with("SELECT")
            || sql_trim.starts_with("PRAGMA")
            || sql_trim.starts_with("WITH");
        if is_query {
            // Turso rows do not expose column names directly, so we prepare a statement
            // and capture column metadata up-front for a stable JSON response shape.
            let mut stmt = conn.prepare(sql).await.context(QuerySnafu)?;
            let column_names: Vec<String> = stmt
                .columns()
                .iter()
                .map(|c| c.name().to_string())
                .collect();
            let values: Vec<TursoValue> = params.iter().map(DbValue::to_turso_value).collect();
            let mut rows = stmt
                .query(params_from_iter(values))
                .await
                .context(QuerySnafu)?;
            let mut results = Vec::new();
            while let Some(row) = rows.next().await.context(QuerySnafu)? {
                let mut columns = BTreeMap::new();
                for (idx, name) in column_names.iter().enumerate() {
                    let value = row.get_value(idx).context(QuerySnafu)?;
                    columns.insert(name.clone(), DbValue::from_turso_value(value));
                }
                results.push(RowData { columns });
            }
            Ok(ExecResult {
                rows: Some(results),
                affected: 0,
            })
        } else {
            // Non-query statements return the affected row count only.
            let values: Vec<TursoValue> = params.iter().map(DbValue::to_turso_value).collect();
            let affected = conn
                .execute(sql, params_from_iter(values))
                .await
                .context(QuerySnafu)?;
            Ok(ExecResult {
                rows: None,
                affected,
            })
        }
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        let conn = self.connection()?;
        let mut rows = conn
            .query(
                "SELECT node_id, addr, created_at_ms, last_seen_ms, is_self FROM nodes;",
                (),
            )
            .await
            .context(QuerySnafu)?;
        let mut nodes = Vec::new();
        while let Some(row) = rows.next().await.context(QuerySnafu)? {
            // Column order matches the SELECT list, so index-based access is safe here.
            let node_id = row.get::<String>(0).context(QuerySnafu)?;
            let addr = row.get::<String>(1).context(QuerySnafu)?;
            let created_at_ms = row.get::<i64>(2).context(QuerySnafu)?;
            let last_seen_ms = row.get::<i64>(3).context(QuerySnafu)?;
            let is_self = row.get::<i64>(4).context(QuerySnafu)? != 0;
            nodes.push(NodeInfo {
                node_id,
                addr,
                created_at_ms,
                last_seen_ms,
                is_self,
            });
        }
        Ok(nodes)
    }

    pub async fn get_self_node(&self) -> Result<Option<NodeInfo>> {
        let conn = self.connection()?;
        let mut rows = conn
            .query(
                "SELECT node_id, addr, created_at_ms, last_seen_ms, is_self FROM nodes WHERE is_self = 1 LIMIT 1;",
                (),
            )
            .await
            .context(QuerySnafu)?;
        if let Some(row) = rows.next().await.context(QuerySnafu)? {
            // Read the local node record, if present.
            let node_id = row.get::<String>(0).context(QuerySnafu)?;
            let addr = row.get::<String>(1).context(QuerySnafu)?;
            let created_at_ms = row.get::<i64>(2).context(QuerySnafu)?;
            let last_seen_ms = row.get::<i64>(3).context(QuerySnafu)?;
            let is_self = row.get::<i64>(4).context(QuerySnafu)? != 0;
            return Ok(Some(NodeInfo {
                node_id,
                addr,
                created_at_ms,
                last_seen_ms,
                is_self,
            }));
        }
        Ok(None)
    }

    pub async fn upsert_nodes(&self, nodes: &[NodeInfo]) -> Result<()> {
        let conn = self.connection()?;
        // Each node is upserted to keep cluster membership eventually consistent.
        for node in nodes {
            conn.execute(
                r#"
                INSERT INTO nodes (node_id, addr, created_at_ms, last_seen_ms, is_self)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(node_id) DO UPDATE SET
                    addr = excluded.addr,
                    last_seen_ms = excluded.last_seen_ms,
                    is_self = CASE WHEN nodes.is_self = 1 THEN 1 ELSE excluded.is_self END;
                "#,
                turso::params![
                    node.node_id.as_str(),
                    node.addr.as_str(),
                    node.created_at_ms,
                    node.last_seen_ms,
                    if node.is_self { 1 } else { 0 },
                ],
            )
            .await
            .context(QuerySnafu)?;
        }
        Ok(())
    }

    pub async fn mark_self_node(&self, node_id: &str, addr: &str) -> Result<NodeInfo> {
        let now = current_time_ms();
        let node = NodeInfo {
            node_id: node_id.to_string(),
            addr: addr.to_string(),
            created_at_ms: now,
            last_seen_ms: now,
            is_self: true,
        };
        let conn = self.connection()?;
        conn.execute(
            r#"
            INSERT INTO nodes (node_id, addr, created_at_ms, last_seen_ms, is_self)
            VALUES (?1, ?2, ?3, ?4, 1)
            ON CONFLICT(node_id) DO UPDATE SET
                addr = excluded.addr,
                last_seen_ms = excluded.last_seen_ms,
                is_self = 1;
            "#,
            turso::params![node.node_id.as_str(), node.addr.as_str(), now, now],
        )
        .await
        .context(QuerySnafu)?;
        Ok(node)
    }

    pub async fn update_node_seen(&self, node_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "UPDATE nodes SET last_seen_ms = ?1 WHERE node_id = ?2;",
            turso::params![current_time_ms(), node_id],
        )
        .await
        .context(QuerySnafu)?;
        Ok(())
    }

    pub async fn delete_node(&self, node_id: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "DELETE FROM nodes WHERE node_id = ?1;",
            turso::params![node_id],
        )
        .await
        .context(QuerySnafu)?;
        Ok(())
    }
}

pub fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
