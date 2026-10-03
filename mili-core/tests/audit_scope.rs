//! The audit scope has to describe the crate as it is, not as it was.
//!
//! `docs/AUDIT_SCOPE.md` is the document an auditor reads to find out what they
//! are being asked to look at. A scope document that has quietly fallen behind the
//! code is worse than none, because it is evidence: it says the attack surface was
//! considered, and an auditor who trusts it will spend their time on the modules it
//! lists. So the one property worth enforcing is that it cannot go stale without a
//! test failing.
//!
//! This checks the module list both ways. Every module `lib.rs` declares has to be
//! named in the document, and every module name the document mentions has to exist.
//! The first direction is the one that matters: it means adding a module is a
//! decision about the surface that cannot be made silently.
//!
//! Private modules are in scope too, and the table's own column is what
//! distinguishes a private module whose items are re-exported from one that is
//! internal only. Both are worth an auditor's time and neither is reachable enough
//! to be found by looking at the public API alone.
//!
//! It deliberately does not check line counts. They were tempting, and they would
//! fail on every ordinary edit, which is the surest way to get a check deleted.

/// The crate root, which is where the module declarations live.
const LIB: &str = include_str!("../src/lib.rs");
const SCOPE: &str = include_str!("../../docs/AUDIT_SCOPE.md");

/// Extracts the module names from the `mod foo;` and `pub mod foo;` lines.
///
/// Written by hand rather than pulled from the compiler because the compiler cannot
/// be asked this question: it would tell us which modules exist, not which ones the
/// document claims to have reviewed. That difference is the entire point of the test.
fn declared_modules(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        // `pub mod` has to be tried first: `strip_prefix("mod ")` does not match it,
        // but a plain suffix search would find `mod ` inside `pub mod ` and record
        // the same name twice.
        let rest = match line.strip_prefix("pub mod ") {
            Some(rest) => Some(rest),
            None => line.strip_prefix("mod "),
        };
        if let Some(rest) = rest {
            let name: String = rest
                .trim_end_matches(';')
                .trim()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                names.push(name);
            }
        }
    }
    names
}

#[test]
fn every_module_is_in_the_audit_scope() {
    let modules = declared_modules(LIB);
    assert!(
        modules.len() >= 8,
        "only found {} modules in lib.rs, so this test is not reading lib.rs the \
         way it thinks it is: {modules:?}",
        modules.len()
    );

    for module in &modules {
        assert!(
            SCOPE.contains(&format!("| `{module}` |")),
            "`{module}` is declared in lib.rs and has no row in the table in \
             docs/AUDIT_SCOPE.md. A new module needs a row there, with whether its \
             items are reachable from outside the crate, and a line under 'Entry \
             points' if a caller can now reach something new."
        );
    }
}

#[test]
fn the_audit_scope_does_not_describe_modules_that_do_not_exist() {
    // The other direction. A module that was renamed or removed leaves a row behind,
    // and a row pointing at nothing is the kind of thing an auditor trusts.
    let modules = declared_modules(LIB);
    for row in SCOPE.lines().filter(|line| line.starts_with("| `")) {
        let name: String = row
            .split('`')
            .nth(1)
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() || name == "Module" {
            continue;
        }
        assert!(
            modules.contains(&name),
            "docs/AUDIT_SCOPE.md has a row for `{name}`, which is not a module of \
             mili-core. Either the module was renamed or the table is stale, and an \
             auditor reading it would be misled either way."
        );
    }
}

#[test]
fn the_audit_scope_does_not_claim_an_audit_that_has_not_happened() {
    // The document opens by saying no third party has audited mili. That sentence is
    // load-bearing in a way a later edit could quietly undo, and an audit-readiness
    // document that implies an audit has happened is the worst kind of wrong.
    assert!(
        SCOPE.contains("No third party has audited mili"),
        "docs/AUDIT_SCOPE.md must keep stating that no third party has audited mili"
    );
    assert!(
        SCOPE.contains("## Status"),
        "the audit status belongs under a heading of its own, so it cannot be \
         scrolled past"
    );
}

#[test]
fn the_entry_point_list_covers_every_reachable_module() {
    // The table says what is in scope. This says what a caller can actually reach,
    // which is the shorter list and the one an attacker reads. A module whose items
    // are re-exported has to appear under "Entry points" as well, because reaching
    // it does not require the module to be public.
    //
    // The reachable set is taken from the `pub use` lines in the crate root rather
    // than from the table's own "Surface" column, so the document is checked against
    // the code and not against itself.
    let re_exported: Vec<String> = LIB
        .lines()
        .filter(|line| line.trim_start().starts_with("pub use "))
        .filter_map(|line| line.split("crate::").nth(1))
        .filter_map(|rest| rest.split([':', '{']).next())
        .map(|name| name.trim().to_string())
        .filter(|name| declared_modules(LIB).contains(name))
        .collect();

    assert!(
        !re_exported.is_empty(),
        "no re-exported module was found, so this test is not reading lib.rs the \
         way it thinks it is"
    );

    for module in re_exported {
        let listed = SCOPE
            .lines()
            .skip_while(|line| !line.starts_with("## Entry points"))
            .any(|line| line.contains(&format!("`{module}`")));
        assert!(
            listed,
            "`{module}` has re-exported items, so a caller can reach it, but it is \
             not named under 'Entry points' in docs/AUDIT_SCOPE.md"
        );
    }
}
