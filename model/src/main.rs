use miracache_model::{check_variant, run_sim, variant, variants, Bounds, Outcome, Variant};
use std::process::ExitCode;

const USAGE: &str = "\
miracache protocol model (design spec section 8)

USAGE:
  miracache-model check [--variant NAME|all|passing|teeth] [--bounds tiny|ci|small|replica3|drain|nightly]
                        [--mode bfs|sim] [--threads N] [--seed N] [--sim-states N] [--set K=V] [--full] [--quiet]
  miracache-model list

  --variant     default: `default` (the correct protocol)
  --bounds      default: small
  --threads     checker threads (default 2)
  --mode        default: bfs for tiny/small (exhaustive), sim for nightly (random simulation)
  --sim-states  simulation budget in visited states (default 20000000)
  --seed        simulation seed (default 20261109)
  --set K=V     override one bound, e.g. --set ops=3 (repeatable)
  --max-states  give up (partial result) after generating N states in bfs mode
  --full        never stop early: explore the whole state space even for teeth variants
  --quiet       do not print counterexample traces
";

struct Opts {
    variant: String,
    bounds: String,
    mode: Option<String>,
    threads: usize,
    seed: u64,
    sim_states: usize,
    full: bool,
    quiet: bool,
    sets: Vec<String>,
    max_states: Option<usize>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("list") => {
            for v in variants() {
                let exp = if v.expect_pass() {
                    "PASS".to_string()
                } else {
                    format!("FAIL {}", v.must_fail.join(", "))
                };
                println!("{:<20} {:<70} expect: {}", v.name, v.what, exp);
            }
            ExitCode::SUCCESS
        }
        Some("check") => check(&args[1..]),
        _ => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check(args: &[String]) -> ExitCode {
    let mut o = Opts {
        variant: "default".into(),
        bounds: "small".into(),
        mode: None,
        threads: 2,
        seed: 20261109,
        sim_states: 20_000_000,
        full: false,
        quiet: false,
        sets: vec![],
        max_states: None,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().unwrap_or_else(|| {
            eprintln!("missing value for {a}");
            std::process::exit(2)
        });
        match a.as_str() {
            "--variant" => o.variant = val(),
            "--bounds" => o.bounds = val(),
            "--mode" => o.mode = Some(val()),
            "--threads" => o.threads = val().parse().expect("--threads N"),
            "--seed" => o.seed = val().parse().expect("--seed N"),
            "--sim-states" => o.sim_states = val().parse().expect("--sim-states N"),
            "--set" => o.sets.push(val()),
            "--max-states" => o.max_states = Some(val().parse().expect("--max-states N")),
            "--full" => o.full = true,
            "--quiet" => o.quiet = true,
            _ => {
                eprintln!("unknown argument {a}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(mut bounds) = Bounds::by_name(&o.bounds) else {
        eprintln!("unknown bounds {}", o.bounds);
        return ExitCode::from(2);
    };
    for kv in &o.sets {
        let ok = kv.split_once('=').is_some_and(|(k, v)| v.parse().is_ok_and(|v| bounds.set(k, v)));
        if !ok {
            eprintln!("bad --set {kv} (expected name=value, e.g. ops=3)");
            return ExitCode::from(2);
        }
    }
    let mode = o.mode.clone().unwrap_or_else(|| if o.bounds == "nightly" { "sim".into() } else { "bfs".into() });
    let selected: Vec<Variant> = match o.variant.as_str() {
        "all" => variants(),
        "passing" => variants().into_iter().filter(|v| v.expect_pass()).collect(),
        "teeth" => variants().into_iter().filter(|v| !v.expect_pass()).collect(),
        name => match variant(name) {
            Some(v) => vec![v],
            None => {
                eprintln!("unknown variant {name}; try `list`");
                return ExitCode::from(2);
            }
        },
    };
    println!("bounds {}: {:?}", o.bounds, bounds);
    let mut all_ok = true;
    for v in &selected {
        let cfg = v.cfg(bounds, o.full);
        println!("\n=== variant {} ({}) ===", v.name, v.what);
        let out = if mode == "sim" {
            println!("mode: random simulation, seed {}, budget {} states, {} threads", o.seed, o.sim_states, o.threads);
            run_sim(cfg, o.seed, o.sim_states, o.threads)
        } else {
            let early = !v.explore_all(&bounds, o.full);
            println!(
                "mode: breadth-first, {}, {} threads{}",
                if early { "stops once the expected counterexamples are found" } else { "exhaustive" },
                o.threads,
                if cfg.b != bounds { format!("\nbounds trimmed for this variant: {:?}", cfg.b) } else { String::new() }
            );
            check_variant(v, bounds, o.threads, o.full, o.max_states)
        };
        all_ok &= report(v, &out, o.quiet);
    }
    if all_ok {
        println!("\nRESULT: every variant behaved as expected");
        ExitCode::SUCCESS
    } else {
        println!("\nRESULT: MISMATCH (see above)");
        ExitCode::FAILURE
    }
}

fn report(v: &Variant, out: &Outcome, quiet: bool) -> bool {
    println!(
        "states generated {}, unique {}, max depth {}, {:.1}s{}",
        out.states,
        out.unique,
        out.depth,
        out.elapsed.as_secs_f64(),
        if out.complete { " (whole reachable state space)" } else { " (partial exploration)" }
    );
    let verb = if out.complete { "HOLDS" } else { "no counterexample" };
    println!("{verb}: {}", out.held.join(", "));
    if !out.not_applicable.is_empty() {
        println!("not applicable (trivially true here, not a pass): {}", out.not_applicable.join(", "));
    }
    if !out.witnessed.is_empty() {
        println!("reachable: {}", out.witnessed.join("; "));
    }
    if !out.unwitnessed.is_empty() {
        println!("not reached: {}", out.unwitnessed.join("; "));
    }
    for (name, trace) in &out.failed {
        println!("COUNTEREXAMPLE for {name} ({} steps)", trace.lines().filter(|l| l.contains(". ")).count());
        if !quiet {
            print!("{trace}");
        }
    }
    let failed = out.failed_names();
    let missing: Vec<_> = v.must_fail.iter().filter(|n| !failed.contains(*n)).collect();
    let unexpected: Vec<_> = failed
        .iter()
        .filter(|n| !v.must_fail.contains(n) && !v.may_fail.contains(n))
        .collect();
    let mut ok = true;
    if out.mode == "bfs" && !missing.is_empty() {
        println!("UNEXPECTED: no counterexample for {missing:?}");
        ok = false;
    }
    if !unexpected.is_empty() {
        println!("UNEXPECTED: counterexample for {unexpected:?}");
        ok = false;
    }
    if v.expect_pass() && out.complete && !out.unwitnessed.is_empty() && v.name == "default" {
        println!("UNEXPECTED: sanity witnesses not reachable");
        ok = false;
    }
    println!("verdict: {}", if ok { "as expected" } else { "MISMATCH" });
    ok
}
