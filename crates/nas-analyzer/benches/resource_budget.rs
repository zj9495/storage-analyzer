use std::hint::black_box;
use std::time::Instant;

use nas_analyzer::export::{
    ExportFormat, ExportLimits, ExportManifest, ExportManifestOptions, ExportRow, ExportSchema,
    ExportScope, ExportSection, QuerySpec, render_export,
};
use nas_analyzer::runtime::MemoryBudgetController;
use serde_json::{Map, Value, json};

fn rows(count: usize) -> Vec<ExportRow> {
    (0..count)
        .map(|index| {
            let mut values = Map::new();
            values.insert(
                "report_id".into(),
                json!("00000000-0000-4000-8000-000000000001"),
            );
            values.insert("source_name".into(), json!("benchmark"));
            values.insert(
                "relative_path_display".into(),
                Value::String(format!("folder/file-{index}.bin")),
            );
            values.insert("owner_uid".into(), json!(1000));
            values.insert("category".into(), json!("other"));
            values.insert("logical_size_bytes".into(), json!(index.to_string()));
            values.insert(
                "allocated_size_estimate_bytes".into(),
                json!(index.to_string()),
            );
            values.insert("mtime".into(), json!("2026-01-01T00:00:00Z"));
            values.insert("atime".into(), json!("2026-01-01T00:00:00Z"));
            values.insert("status".into(), json!("present"));
            ExportRow::from_object(values)
        })
        .collect()
}

fn main() {
    let source_rows = rows(10_000);
    let schema = ExportSchema::new(Vec::<String>::new()).expect("benchmark schema");
    let manifest = ExportManifest::new(
        "00000000-0000-4000-8000-000000000001",
        ExportSection::Files,
        ExportFormat::Csv,
        ExportScope::Current,
        QuerySpec::default(),
        ExportManifestOptions::new("UTC", false, true),
    )
    .expect("benchmark manifest");
    let memory = MemoryBudgetController::new(128, 512).expect("memory budget");

    let start = Instant::now();
    let mut rows_written = 0_u64;
    for _ in 0..3 {
        memory.sample_now().expect("memory sample");
        let limits = ExportLimits::new(64 * 1024 * 1024, 1).expect("benchmark limits");
        let (output, stats) =
            render_export(&manifest, &schema, &source_rows, limits).expect("benchmark export");
        rows_written = rows_written.saturating_add(stats.rows_written);
        black_box(output);
    }
    let elapsed = start.elapsed();
    let snapshot = memory.snapshot();
    println!(
        "resource_budget export_rows={} elapsed_ms={} rows_per_sec={} api_rss_bytes={:?} worker_rss_bytes={:?}",
        rows_written,
        elapsed.as_millis(),
        (rows_written as f64 / elapsed.as_secs_f64()) as u64,
        snapshot.process_rss_bytes,
        snapshot.process_rss_bytes,
    );
}
