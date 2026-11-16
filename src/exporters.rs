//! Multi-format report exporters: ANSI Terminal Table, Canonical JSON, and OASIS SARIF v2.1.0.

#![forbid(unsafe_code)]

use crate::auditor::AirgapAuditReport;

/// Renders the audit report as an ANSI colored terminal table.
pub fn export_table(report: &AirgapAuditReport) -> String {
    let mut out = String::new();
    out.push_str("\n========================================================================================\n");
    out.push_str("          LOGIHERTZ AIR-GAP DATA DIODE ENCLAVE SECURITY AUDIT REPORT\n");
    out.push_str("========================================================================================\n");
    out.push_str(&format!(
        " Policy Profile:  {}\n",
        report::escape_line(&report.policy_name)
    ));
    out.push_str(&format!(" Total Rules:     {}\n", report.total_rules));
    out.push_str(&format!(
        " Passed:          \x1b[1;32m{}\x1b[0m\n",
        report.passed_rules
    ));
    out.push_str(&format!(
        " Failed:          \x1b[1;31m{}\x1b[0m\n",
        report.failed_rules
    ));
    out.push_str(&format!(" Deductions:      -{}\n", report.total_deductions));

    if report.posture_score >= 80 {
        out.push_str(&format!(
            " Posture Score:   \x1b[1;32m{} / 100 [PASS]\x1b[0m\n",
            report.posture_score
        ));
    } else {
        out.push_str(&format!(
            " Posture Score:   \x1b[1;31m{} / 100 [FAIL]\x1b[0m\n",
            report.posture_score
        ));
    }

    out.push_str("----------------------------------------------------------------------------------------\n");
    out.push_str(&format!(
        " {:<14} | {:<8} | {:<4} | {:<6} | {:<42}\n",
        "Rule ID", "Severity", "Ded.", "Status", "Rule Name"
    ));
    out.push_str("----------------------------------------------------------------------------------------\n");

    for f in &report.findings {
        let status_str = if f.passed {
            "\x1b[1;32mPASS\x1b[0m  "
        } else {
            "\x1b[1;31mFAIL\x1b[0m  "
        };
        let ded_val = if f.passed { 0 } else { f.deduction };
        out.push_str(&format!(
            " {:<14} | {:<8} | -{:<3} | {} | {:<42}\n",
            f.rule_id,
            f.severity.as_str(),
            ded_val,
            status_str,
            f.rule_name
        ));
        if !f.passed {
            out.push_str(&format!("   -> Details:        {}\n", f.details));
            out.push_str(&format!("   -> Recommendation: {}\n", f.recommendation));
        }
    }

    out.push_str("========================================================================================\n\n");
    out
}

/// Renders the audit report as Canonical JSON.
pub fn export_json(report: &AirgapAuditReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"policy_name\": \"{}\",\n",
        escape_json(&report.policy_name)
    ));
    out.push_str(&format!("  \"total_rules\": {},\n", report.total_rules));
    out.push_str(&format!("  \"passed_rules\": {},\n", report.passed_rules));
    out.push_str(&format!("  \"failed_rules\": {},\n", report.failed_rules));
    out.push_str(&format!(
        "  \"total_deductions\": {},\n",
        report.total_deductions
    ));
    out.push_str(&format!("  \"posture_score\": {},\n", report.posture_score));
    out.push_str(&format!(
        "  \"status\": \"{}\",\n",
        if report.posture_score >= 80 {
            "PASS"
        } else {
            "FAIL"
        }
    ));
    out.push_str("  \"findings\": [\n");

    for (i, f) in report.findings.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"rule_id\": \"{}\",\n", f.rule_id));
        out.push_str(&format!(
            "      \"rule_name\": \"{}\",\n",
            escape_json(f.rule_name)
        ));
        out.push_str(&format!("      \"cwe_id\": \"{}\",\n", f.cwe_id));
        out.push_str(&format!(
            "      \"severity\": \"{}\",\n",
            f.severity.as_str()
        ));
        out.push_str(&format!("      \"deduction\": {},\n", f.deduction));
        out.push_str(&format!("      \"passed\": {},\n", f.passed));
        out.push_str(&format!(
            "      \"details\": \"{}\",\n",
            escape_json(&f.details)
        ));
        out.push_str(&format!(
            "      \"recommendation\": \"{}\"\n",
            escape_json(f.recommendation)
        ));
        out.push_str("    }");
        if i + 1 < report.findings.len() {
            out.push(',');
        }
        out.push('\n');
    }

    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

/// Renders the audit report into OASIS SARIF v2.1.0 format.
pub fn export_sarif(report: &AirgapAuditReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n");
    out.push_str("  \"version\": \"2.1.0\",\n");
    out.push_str("  \"runs\": [\n");
    out.push_str("    {\n");
    out.push_str("      \"tool\": {\n");
    out.push_str("        \"driver\": {\n");
    out.push_str("          \"name\": \"lh-airgap-sync\",\n");
    out.push_str("          \"version\": \"0.1.0\",\n");
    out.push_str("          \"informationUri\": \"https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-airgap-sync-protocol\",\n");
    out.push_str("          \"rules\": [\n");

    for (i, f) in report.findings.iter().enumerate() {
        out.push_str("            {\n");
        out.push_str(&format!("              \"id\": \"{}\",\n", f.rule_id));
        out.push_str(&format!(
            "              \"name\": \"{}\",\n",
            escape_json(f.rule_name)
        ));
        out.push_str(&format!(
            "              \"shortDescription\": {{ \"text\": \"{}\" }},\n",
            escape_json(f.rule_name)
        ));
        out.push_str(&format!(
            "              \"help\": {{ \"text\": \"{}\" }},\n",
            escape_json(f.recommendation)
        ));
        out.push_str(&format!(
            "              \"defaultConfiguration\": {{ \"level\": \"{}\" }}\n",
            f.severity.sarif_level()
        ));
        out.push_str("            }");
        if i + 1 < report.findings.len() {
            out.push(',');
        }
        out.push('\n');
    }

    out.push_str("          ]\n");
    out.push_str("        }\n");
    out.push_str("      },\n");
    out.push_str("      \"results\": [\n");

    let failed_findings: Vec<_> = report.findings.iter().filter(|f| !f.passed).collect();
    for (i, f) in failed_findings.iter().enumerate() {
        out.push_str("        {\n");
        out.push_str(&format!("          \"ruleId\": \"{}\",\n", f.rule_id));
        out.push_str(&format!(
            "          \"level\": \"{}\",\n",
            f.severity.sarif_level()
        ));
        out.push_str(&format!(
            "          \"message\": {{ \"text\": \"{}. {}\" }},\n",
            escape_json(&f.details),
            escape_json(f.recommendation)
        ));
        out.push_str("          \"locations\": [\n");
        out.push_str("            {\n");
        out.push_str("              \"physicalLocation\": {\n");
        out.push_str(&format!(
            "                \"artifactLocation\": {{ \"uri\": \"{}\" }}\n",
            escape_json(&report.policy_name)
        ));
        out.push_str("              }\n");
        out.push_str("            }\n");
        out.push_str("          ]\n");
        out.push_str("        }");
        if i + 1 < failed_findings.len() {
            out.push(',');
        }
        out.push('\n');
    }

    out.push_str("      ]\n");
    out.push_str("    }\n");
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

mod report {
    pub fn escape_line(s: &str) -> String {
        s.replace('\n', " ").replace('\r', "")
    }
}
