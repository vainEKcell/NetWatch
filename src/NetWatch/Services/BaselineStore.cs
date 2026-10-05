using System.IO;
using Microsoft.Data.Sqlite;
using NetWatch.Models;

namespace NetWatch.Services;

/// 行为基线持久化（SQLite，WAL）。以 SoftwareIdentity 为主体的跨会话记账。
/// 写入路径：UI 每 8 秒把“脏实体 + 关系增量”在单个事务里批量 UPSERT；崩溃最多丢一个刷写窗口。
public sealed class BaselineStore
{
    private readonly AppSettings _settings;
    private readonly SqliteConnection _conn;

    public BaselineStore(AppSettings settings)
    {
        _settings = settings;
        Directory.CreateDirectory(AppSettings.Dir);
        _conn = new SqliteConnection($"Data Source={AppSettings.DbPath};Mode=ReadWriteCreate");
        _conn.Open();
        Exec("PRAGMA journal_mode=WAL;");
        Exec("PRAGMA synchronous=NORMAL;");
        EnsureSchema();
    }

    private void Exec(string sql)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private void EnsureSchema()
    {
        Exec("""
            CREATE TABLE IF NOT EXISTS identities(
                key TEXT PRIMARY KEY,
                kind INTEGER NOT NULL,
                display_name TEXT,
                cert_subject TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS identity_dest(
                identity_key TEXT NOT NULL,
                dest_key TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                conn_count INTEGER NOT NULL DEFAULT 0,
                up_bytes INTEGER NOT NULL DEFAULT 0,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(identity_key, dest_key));
            CREATE INDEX IF NOT EXISTS ix_identity_dest_dest ON identity_dest(dest_key);
            CREATE TABLE IF NOT EXISTS destinations(
                key TEXT PRIMARY KEY,
                domain TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS identity_paths(
                identity_key TEXT NOT NULL,
                path TEXT NOT NULL,
                PRIMARY KEY(identity_key, path));
            """);
        // unk: 身份（PID 级临时身份）无跨会话意义，不入库；清掉历史脏数据
        Exec("DELETE FROM identities WHERE key LIKE 'unk:%';");
        Exec("DELETE FROM identity_dest WHERE identity_key LIKE 'unk:%';");
    }

    // ---------- 查询 ----------

    /// 跨会话“首见于”回填：库里若更早，则更新内存身份。
    /// 身份合并：同一文件路径曾以其他身份（如未签名时期的路径身份）出现过，取全部相关身份的最早 first_seen。
    /// 使用独立短连接——主连接被 UI 线程的刷写占用，SqliteConnection 非线程安全。
    public void BackfillIdentity(SoftwareIdentity id)
    {
        try
        {
            using var conn = new SqliteConnection($"Data Source={AppSettings.DbPath};Mode=ReadOnly");
            conn.Open();
            DateTime? earliest = null;

            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = "SELECT MIN(first_seen) FROM identities WHERE key=$k";
                cmd.Parameters.AddWithValue("$k", id.Key);
                if (cmd.ExecuteScalar() is long own && own > 0)
                    earliest = DateTimeOffset.FromUnixTimeSeconds(own).UtcDateTime;
            }

            using (var cmd = conn.CreateCommand())
            {
                // 同路径的其他身份（未签名→签名的演变即由此合并）
                cmd.CommandText = """
                    SELECT MIN(i.first_seen)
                    FROM identities i
                    WHERE i.key IN (
                        SELECT p2.identity_key FROM identity_paths p2
                        WHERE p2.path IN (SELECT path FROM identity_paths WHERE identity_key = $k))
                    """;
                cmd.Parameters.AddWithValue("$k", id.Key);
                if (cmd.ExecuteScalar() is long merged && merged > 0)
                {
                    var utc = DateTimeOffset.FromUnixTimeSeconds(merged).UtcDateTime;
                    if (earliest == null || utc < earliest) earliest = utc;
                }
            }

            if (earliest != null && earliest < id.FirstSeenUtc)
                id.FirstSeenUtc = earliest.Value;
            id.LastSeenUtc = DateTime.UtcNow;
        }
        catch (Exception ex) { Log.Error("基线回填失败", ex); }
    }

    // ---------- 写入 ----------

    public void Flush(IReadOnlyList<SoftwareIdentity> identities,
                      IReadOnlyList<DestinationEntity> destinations,
                      IReadOnlyList<RelationRow> relations)
    {
        if (_settings.BaselinePaused) return;
        try
        {
            using var tx = _conn.BeginTransaction();
            foreach (var id in identities)
            {
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO identities(key, kind, display_name, cert_subject, first_seen, last_seen)
                    VALUES($k, $kind, $dn, $cs, $fs, $ls)
                    ON CONFLICT(key) DO UPDATE SET
                        kind=excluded.kind, display_name=excluded.display_name,
                        cert_subject=excluded.cert_subject, last_seen=excluded.last_seen;
                    """;
                cmd.Parameters.AddWithValue("$k", id.Key);
                cmd.Parameters.AddWithValue("$kind", (long)id.Kind);
                cmd.Parameters.AddWithValue("$dn", id.DisplayName);
                cmd.Parameters.AddWithValue("$cs", (object?)id.CertSubject ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$fs", ToUnix(id.FirstSeenUtc));
                cmd.Parameters.AddWithValue("$ls", ToUnix(id.LastSeenUtc));
                cmd.ExecuteNonQuery();

                foreach (var path in id.Paths)
                {
                    using var pc = _conn.CreateCommand();
                    pc.Transaction = tx;
                    pc.CommandText = "INSERT OR IGNORE INTO identity_paths(identity_key, path) VALUES($k, $p)";
                    pc.Parameters.AddWithValue("$k", id.Key);
                    pc.Parameters.AddWithValue("$p", path.ToLowerInvariant());
                    pc.ExecuteNonQuery();
                }
            }

            foreach (var d in destinations)
            {
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO destinations(key, domain, first_seen, last_seen)
                    VALUES($k, $dm, $fs, $ls)
                    ON CONFLICT(key) DO UPDATE SET last_seen=excluded.last_seen;
                    """;
                cmd.Parameters.AddWithValue("$k", d.Key);
                cmd.Parameters.AddWithValue("$dm", (object?)d.Domain ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$fs", ToUnix(d.FirstSeenUtc));
                cmd.Parameters.AddWithValue("$ls", ToUnix(d.LastSeenUtc));
                cmd.ExecuteNonQuery();
            }

            foreach (var r in relations)
            {
                using var cmd = _conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO identity_dest(identity_key, dest_key, first_seen, last_seen, conn_count, up_bytes, down_bytes)
                    VALUES($ik, $dk, $fs, $ls, $c, $u, $d)
                    ON CONFLICT(identity_key, dest_key) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        conn_count = conn_count + excluded.conn_count,
                        up_bytes = up_bytes + excluded.up_bytes,
                        down_bytes = down_bytes + excluded.down_bytes;
                    """;
                cmd.Parameters.AddWithValue("$ik", r.IdentityKey);
                cmd.Parameters.AddWithValue("$dk", r.DestKey);
                cmd.Parameters.AddWithValue("$fs", ToUnix(r.FirstSeenUtc));
                cmd.Parameters.AddWithValue("$ls", ToUnix(r.LastSeenUtc));
                cmd.Parameters.AddWithValue("$c", r.CountDelta);
                cmd.Parameters.AddWithValue("$u", r.UpDelta);
                cmd.Parameters.AddWithValue("$d", r.DownDelta);
                cmd.ExecuteNonQuery();
            }

            tx.Commit();
        }
        catch (Exception ex) { Log.Error("基线刷写失败", ex); }
    }

    // ---------- 清理 ----------

    public int Cleanup(DateTime baselineCutoff)
    {
        try
        {
            int total;
            using (var cmd = _conn.CreateCommand())
            {
                cmd.CommandText = """
                    DELETE FROM identity_dest WHERE last_seen < $c;
                    DELETE FROM identities WHERE last_seen < $c;
                    DELETE FROM destinations WHERE last_seen < $c;
                    """;
                cmd.Parameters.AddWithValue("$c", ToUnix(baselineCutoff));
                total = cmd.ExecuteNonQuery();
            }
            Exec("PRAGMA wal_checkpoint(TRUNCATE);");
            return total;
        }
        catch (Exception ex) { Log.Error("基线清理失败", ex); return 0; }
    }

    public static long DbSizeBytes =>
        File.Exists(AppSettings.DbPath) ? new FileInfo(AppSettings.DbPath).Length : 0;

    private static long ToUnix(DateTime utc) => new DateTimeOffset(utc).ToUnixTimeSeconds();
}

/// (软件身份 → 目的地) 关系的本次刷写周期增量
public sealed record RelationRow(
    string IdentityKey, string DestKey,
    long CountDelta, long UpDelta, long DownDelta,
    DateTime FirstSeenUtc, DateTime LastSeenUtc);
