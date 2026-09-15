//! Post-traversal finalization: DFS interval assignment and SQL-side
//! aggregates (spec 5.1, 8.1). Everything streams with keyset pagination;
//! no full-table materialization in Rust memory.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{AppError, AppResult, ErrorCode};

use super::ScanControl;

const DFS_PAGE: i64 = 256;

fn internal(msg: impl Into<String>) -> AppError {
    AppError::new(ErrorCode::Internal, msg)
}

/// Assign nested-set dfs_left/dfs_right to every entry of one source via an
/// iterative DFS over the index (stack holds only the current path spine;
/// children are fetched one page at a time by keyset). Returns Ok(true) when
/// cancelled; the transaction is then rolled back by dropping it.
pub(super) fn assign_dfs_intervals(
    conn: &Connection,
    source_id: &str,
    control: &ScanControl,
) -> AppResult<bool> {
    let root: Option<i64> = conn
        .query_row(
            "SELECT entry_id FROM entries WHERE source_id = ?1 AND parent_entry_id IS NULL",
            params![source_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| internal(format!("find root entry: {e}")))?;
    let Some(root_id) = root else {
        return Ok(false);
    };

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| internal(format!("begin dfs tx: {e}")))?;
    let mut next_child = tx
        .prepare(
            "SELECT entry_id FROM entries \
             WHERE parent_entry_id = ?1 AND entry_id > ?2 ORDER BY entry_id LIMIT 1",
        )
        .map_err(|e| internal(format!("prepare dfs children: {e}")))?;
    let mut set_left = tx
        .prepare("UPDATE entries SET dfs_left = ?2 WHERE entry_id = ?1")
        .map_err(|e| internal(format!("prepare dfs_left: {e}")))?;
    let mut set_right = tx
        .prepare("UPDATE entries SET dfs_right = ?2 WHERE entry_id = ?1")
        .map_err(|e| internal(format!("prepare dfs_right: {e}")))?;

    struct Frame {
        id: i64,
        last_child: i64,
    }

    let mut counter: i64 = 0;
    let mut visited: u64 = 0;
    let mut stack: Vec<Frame> = Vec::new();
    counter += 1;
    set_left
        .execute(params![root_id, counter])
        .map_err(|e| internal(format!("dfs_left: {e}")))?;
    stack.push(Frame {
        id: root_id,
        last_child: 0,
    });

    while let Some(frame) = stack.last() {
        let frame_id = frame.id;
        let last_child = frame.last_child;
        let child: Option<i64> = next_child
            .query_row(params![frame_id, last_child], |r| r.get(0))
            .optional()
            .map_err(|e| internal(format!("dfs child: {e}")))?;
        match child {
            Some(cid) => {
                if let Some(f) = stack.last_mut() {
                    f.last_child = cid;
                }
                counter += 1;
                set_left
                    .execute(params![cid, counter])
                    .map_err(|e| internal(format!("dfs_left: {e}")))?;
                stack.push(Frame {
                    id: cid,
                    last_child: 0,
                });
                visited += 1;
                if visited.is_multiple_of(4096) && control.is_cancelled() {
                    // Dropping tx rolls back; partial dfs values are not kept.
                    return Ok(true);
                }
            }
            None => {
                counter += 1;
                set_right
                    .execute(params![frame_id, counter])
                    .map_err(|e| internal(format!("dfs_right: {e}")))?;
                stack.pop();
            }
        }
    }
    drop(set_left);
    drop(set_right);
    drop(next_child);
    tx.commit()
        .map_err(|e| internal(format!("commit dfs: {e}")))?;
    Ok(false)
}

/// Compute directory_aggregates (bottom-up over dfs_right ASC so children
/// are always aggregated before their parents), owner_aggregates and
/// category_aggregates. `unique_logical_bytes` and allocated bytes count each
/// reliable identity once per run, attributed to its first-seen (lowest
/// entry_id) path (spec 5.1/5.2 statistical convention).
pub(super) fn compute_aggregates(conn: &Connection, control: &ScanControl) -> AppResult<bool> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| internal(format!("begin aggregates tx: {e}")))?;
    tx.execute_batch(
        "DROP TABLE IF EXISTS temp.first_occurrence;
         CREATE TEMP TABLE first_occurrence(entry_id INTEGER PRIMARY KEY);
         INSERT INTO first_occurrence(entry_id)
             SELECT e.entry_id FROM entries e
             WHERE e.entry_kind = 'regular_file' AND e.file_identity_key IS NOT NULL
               AND e.entry_id = (
                   SELECT MIN(e2.entry_id) FROM entries e2
                   WHERE e2.file_identity_key = e.file_identity_key
               );",
    )
    .map_err(|e| internal(format!("first_occurrence: {e}")))?;

    // Bottom-up: a child's dfs_right is always smaller than its parent's, so
    // iterating directories by dfs_right ASC aggregates children first.
    let mut last_right = 0_i64;
    loop {
        if control.is_cancelled() {
            return Ok(true);
        }
        let page: Vec<(i64, i64)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT entry_id, dfs_right FROM entries \
                    WHERE entry_kind = 'directory' AND dfs_right IS NOT NULL AND dfs_right > ?1 \
                     ORDER BY dfs_right ASC LIMIT ?2",
                )
                .map_err(|e| internal(format!("prepare dir pages: {e}")))?;
            let rows = stmt
                .query_map(params![last_right, DFS_PAGE], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                })
                .map_err(|e| internal(format!("dir page: {e}")))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| internal(format!("dir page row: {e}")))?);
            }
            v
        };
        if page.is_empty() {
            break;
        }
        let mut ins = tx
            .prepare(
                "INSERT INTO directory_aggregates \
                 (entry_id, source_id, file_count, dir_count, logical_bytes, \
                  unique_logical_bytes, allocated_bytes, excluded_count) \
                 SELECT ?1, ?2, \
                   (SELECT COUNT(*) FROM entries \
                    WHERE parent_entry_id = ?1 AND entry_kind = 'regular_file') \
                   + COALESCE((SELECT SUM(a.file_count) FROM directory_aggregates a \
                               JOIN entries p ON a.entry_id = p.entry_id \
                               WHERE p.parent_entry_id = ?1), 0), \
                   (SELECT COUNT(*) FROM entries \
                    WHERE parent_entry_id = ?1 AND entry_kind = 'directory') \
                   + COALESCE((SELECT SUM(a.dir_count) FROM directory_aggregates a \
                               JOIN entries p ON a.entry_id = p.entry_id \
                               WHERE p.parent_entry_id = ?1), 0), \
                   CASE WHEN EXISTS(SELECT 1 FROM entries e \
                                    WHERE e.parent_entry_id = ?1 \
                                      AND e.entry_kind = 'regular_file' \
                                      AND e.size_bytes IS NULL) \
                             OR EXISTS(SELECT 1 FROM directory_aggregates a \
                                       JOIN entries p ON a.entry_id = p.entry_id \
                                       WHERE p.parent_entry_id = ?1 \
                                         AND a.logical_bytes IS NULL) \
                        THEN NULL \
                        ELSE COALESCE((SELECT SUM(size_bytes) FROM entries \
                                       WHERE parent_entry_id = ?1 AND entry_kind = 'regular_file'), 0) \
                           + COALESCE((SELECT SUM(a.logical_bytes) FROM directory_aggregates a \
                                       JOIN entries p ON a.entry_id = p.entry_id \
                                       WHERE p.parent_entry_id = ?1), 0) \
                   END, \
                   CASE WHEN EXISTS(SELECT 1 FROM entries e \
                                    WHERE e.parent_entry_id = ?1 \
                                      AND e.entry_kind = 'regular_file' \
                                      AND (e.file_identity_key IS NULL OR e.size_bytes IS NULL)) \
                             OR EXISTS(SELECT 1 FROM directory_aggregates a \
                                       JOIN entries p ON a.entry_id = p.entry_id \
                                       WHERE p.parent_entry_id = ?1 \
                                         AND a.unique_logical_bytes IS NULL) \
                        THEN NULL \
                        ELSE COALESCE((SELECT SUM(e.size_bytes) FROM entries e \
                                       JOIN first_occurrence f ON f.entry_id = e.entry_id \
                                       WHERE e.parent_entry_id = ?1), 0) \
                           + COALESCE((SELECT SUM(a.unique_logical_bytes) FROM directory_aggregates a \
                                       JOIN entries p ON a.entry_id = p.entry_id \
                                       WHERE p.parent_entry_id = ?1), 0) \
                   END, \
                   CASE WHEN EXISTS(SELECT 1 FROM entries e \
                                    WHERE e.parent_entry_id = ?1 \
                                      AND e.entry_kind = 'regular_file' \
                                      AND (e.file_identity_key IS NULL OR e.allocated_bytes_estimate IS NULL)) \
                             OR EXISTS(SELECT 1 FROM directory_aggregates a \
                                       JOIN entries p ON a.entry_id = p.entry_id \
                                       WHERE p.parent_entry_id = ?1 \
                                         AND a.allocated_bytes IS NULL) \
                        THEN NULL \
                        ELSE COALESCE((SELECT SUM(e.allocated_bytes_estimate) FROM entries e \
                                       JOIN first_occurrence f ON f.entry_id = e.entry_id \
                                       WHERE e.parent_entry_id = ?1), 0) \
                           + COALESCE((SELECT SUM(a.allocated_bytes) FROM directory_aggregates a \
                                       JOIN entries p ON a.entry_id = p.entry_id \
                                       WHERE p.parent_entry_id = ?1), 0) \
                   END, \
                   COALESCE((SELECT n FROM dir_excluded WHERE entry_id = ?1), 0) \
                   + COALESCE((SELECT SUM(a.excluded_count) FROM directory_aggregates a \
                               JOIN entries p ON a.entry_id = p.entry_id \
                               WHERE p.parent_entry_id = ?1), 0)",
            )
            .map_err(|e| internal(format!("prepare dir aggregate: {e}")))?;
        for (id, right) in &page {
            let src: String = tx
                .query_row(
                    "SELECT source_id FROM entries WHERE entry_id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .map_err(|e| internal(format!("dir source lookup: {e}")))?;
            ins.execute(params![id, src])
                .map_err(|e| internal(format!("dir aggregate insert: {e}")))?;
            last_right = *right;
        }
    }

    tx.execute(
        "INSERT INTO owner_aggregates(source_id, uid, file_count, logical_bytes) \
         SELECT source_id, uid, COUNT(*), \
                CASE WHEN COUNT(size_bytes) < COUNT(*) THEN NULL ELSE SUM(size_bytes) END \
         FROM entries WHERE entry_kind = 'regular_file' GROUP BY source_id, uid",
        [],
    )
    .map_err(|e| internal(format!("owner aggregates: {e}")))?;

    tx.execute(
        "INSERT INTO category_aggregates \
         (source_id, category_id, file_count, logical_bytes, allocated_bytes) \
         SELECT e.source_id, e.category_id, COUNT(*), \
                CASE WHEN COUNT(e.size_bytes) < COUNT(*) THEN NULL ELSE SUM(e.size_bytes) END, \
                CASE WHEN SUM(CASE WHEN e.file_identity_key IS NULL \
                                      OR (f.entry_id IS NOT NULL AND e.allocated_bytes_estimate IS NULL) \
                                   THEN 1 ELSE 0 END) > 0 \
                     THEN NULL \
                     ELSE COALESCE(SUM(CASE WHEN f.entry_id IS NOT NULL \
                                            THEN e.allocated_bytes_estimate ELSE 0 END), 0) \
                END \
         FROM entries e LEFT JOIN first_occurrence f ON f.entry_id = e.entry_id \
         WHERE e.entry_kind = 'regular_file' \
         GROUP BY e.source_id, e.category_id",
        [],
    )
    .map_err(|e| internal(format!("category aggregates: {e}")))?;

    tx.commit()
        .map_err(|e| internal(format!("commit aggregates: {e}")))?;
    Ok(false)
}
