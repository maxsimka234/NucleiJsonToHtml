import json
import argparse
import sys
import datetime
from string import Template
import html

# --- HTML Template ---
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nuclei Vulnerability Report</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --text-color: #e2e8f0;
            --card-bg: #1e293b;
            --border-color: #334155;
            --accent-color: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #64748b;
            --unknown: #94a3b8;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }

        h1 { margin: 0; font-size: 2rem; }
        .meta { color: #94a3b8; font-size: 0.9rem; }

        /* Stats Dashboard */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .stat-card {
            background-color: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .stat-value { font-size: 2rem; font-weight: bold; display: block; }
        .stat-label { font-size: 0.9rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }

        /* Severity Colors */
        .text-critical { color: var(--critical); }
        .text-high { color: var(--high); }
        .text-medium { color: var(--medium); }
        .text-low { color: var(--low); }
        .text-info { color: var(--info); }
        .text-unknown { color: var(--unknown); }
        
        .bg-critical { background-color: var(--critical); color: white; }
        .bg-high { background-color: var(--high); color: white; }
        .bg-medium { background-color: var(--medium); color: black; }
        .bg-low { background-color: var(--low); color: white; }
        .bg-info { background-color: var(--info); color: white; }
        .bg-unknown { background-color: var(--unknown); color: white; }

        /* Findings Table */
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .finding-card {
            background-color: var(--card-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            overflow: hidden;
            transition: transform 0.2s ease;
        }

        .finding-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background-color: rgba(255, 255, 255, 0.02);
        }

        .finding-header:hover {
            background-color: rgba(255, 255, 255, 0.05);
        }

        .header-left { display: flex; align-items: center; gap: 15px; }
        
        .severity-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            min-width: 60px;
            text-align: center;
        }

        .finding-title { font-weight: 600; font-size: 1.1rem; }
        .finding-host { color: var(--accent-color); font-family: monospace; }
        
        .finding-details {
            padding: 0 20px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out, padding 0.3s ease;
            background-color: rgba(0, 0, 0, 0.1);
        }

        .finding-card.open .finding-details {
            padding: 20px;
            max-height: 2000px; /* Arbitrary large height */
            border-top: 1px solid var(--border-color);
        }

        .detail-row {
            margin-bottom: 15px;
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
        }

        .detail-label { color: #94a3b8; font-weight: 500; }
        .detail-value { font-family: monospace; word-break: break-all; }

        pre {
            background-color: #0f172a;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            margin: 5px 0;
            white-space: pre-wrap;
             word-wrap: break-word;
        }

        .chevron {
            transition: transform 0.3s ease;
        }
        .finding-card.open .chevron {
            transform: rotate(180deg);
        }

        /* Filter Controls */
        .controls {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .search-box {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: white;
            padding: 8px 12px;
            border-radius: 4px;
            flex-grow: 1;
        }

        .btn {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: #94a3b8;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn:hover, .btn.active {
            background-color: var(--accent-color);
            color: white;
            border-color: var(--accent-color);
        }

    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Nuclei Validation Report</h1>
                <div class="meta">Generated: ${date} | Total Findings: ${total_count}</div>
            </div>
            <div>
                <a href="https://github.com/projectdiscovery/nuclei" target="_blank" style="color: var(--accent-color); text-decoration: none;">Project Discovery</a>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-value text-critical">${critical_count}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-card">
                <span class="stat-value text-high">${high_count}</span>
                <span class="stat-label">High</span>
            </div>
            <div class="stat-card">
                <span class="stat-value text-medium">${medium_count}</span>
                <span class="stat-label">Medium</span>
            </div>
            <div class="stat-card">
                <span class="stat-value text-low">${low_count}</span>
                <span class="stat-label">Low</span>
            </div>
            <div class="stat-card">
                <span class="stat-value text-info">${info_count}</span>
                <span class="stat-label">Info</span>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Search hosts, templates..." onkeyup="filterFindings()">
            <button class="btn active" onclick="filterSeverity('all', this)">All</button>
            <button class="btn" onclick="filterSeverity('critical', this)">Critical</button>
            <button class="btn" onclick="filterSeverity('high', this)">High</button>
            <button class="btn" onclick="filterSeverity('medium', this)">Medium</button>
            <button class="btn" onclick="filterSeverity('low', this)">Low</button>
            <button class="btn" onclick="filterSeverity('info', this)">Info</button>
        </div>

        <div class="findings-list" id="findingsList">
            ${findings_html}
        </div>
    </div>

    <script>
        function toggleDetails(element) {
            const card = element.closest('.finding-card');
            card.classList.toggle('open');
        }

        function filterSeverity(severity, btn) {
            // Update buttons
            document.querySelectorAll('.controls .btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                if (severity === 'all' || card.dataset.severity === severity) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
            // Re-apply search filter if needed
            filterFindings();
        }

        function filterFindings() {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const activeSeverityBtn = document.querySelector('.controls .btn.active');
            const activeSeverity = activeSeverityBtn.innerText.toLowerCase();

            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {
                const text = card.innerText.toLowerCase();
                const severityMatch = activeSeverity === 'all' || card.dataset.severity === activeSeverity;
                const searchMatch = text.includes(query);

                if (severityMatch && searchMatch) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"""

FINDING_TEMPLATE = """
            <div class="finding-card" data-severity="${severity_lower}">
                <div class="finding-header" onclick="toggleDetails(this)">
                    <div class="header-left">
                        <span class="severity-badge bg-${severity_lower}">${severity_upper}</span>
                        <div>
                            <div class="finding-title">${template_name}</div>
                            <div class="finding-host">${host}</div>
                        </div>
                    </div>
                    <div class="chevron">▼</div>
                </div>
                <div class="finding-details">
                    <div class="detail-row">
                        <div class="detail-label">Template ID</div>
                        <div class="detail-value">${template_id}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Matched At</div>
                        <div class="detail-value"><a href="${matched_at}" target="_blank" style="color: var(--accent-color);">${matched_at}</a></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Extracted</div>
                        <div class="detail-value">${extracted_results}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Description</div>
                        <div class="detail-value">${description}</div>
                    </div>
                    ${curl_command}
                    ${request_block}
                    ${response_block}
                </div>
            </div>
"""

def parse_args():
    parser = argparse.ArgumentParser(description="Convert Nuclei JSON output to HTML report")
    parser.add_argument("-i", "--input", required=True, help="Input file containing Nuclei JSON output")
    parser.add_argument("-o", "--output", required=True, help="Output HTML file path")
    return parser.parse_args()

def load_data(filepath):
    data = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            # Try parsing as a JSON array first
            try:
                data = json.loads(content)
                if not isinstance(data, list):
                    data = [data] # Handle single object not valid list
            except json.JSONDecodeError:
                # If that fails, try line-by-line JSON (JSONL)
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError:
                            print(f"Warning: Skipping invalid JSON line: {line[:50]}...", file=sys.stderr)
    except Exception as e:
        print(f"Error reading input file: {e}", file=sys.stderr)
        sys.exit(1)
    
    return data

def get_severity_score(severity):
    ordering = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "unknown": 0
    }
    return ordering.get(severity.lower(), 0)

def generate_report(data, output_file):
    stats = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0
    }
    
    findings_html_list = []
    
    # Sort data by severity (Critical first)
    data.sort(key=lambda x: get_severity_score(x.get("info", {}).get("severity", "unknown")), reverse=True)

    for item in data:
        info = item.get("info", {})
        severity = info.get("severity", "unknown").lower()
        if severity not in stats:
            severity = "unknown"
        stats[severity] += 1
        
        # Prepare data for template
        template_id = item.get("template-id", "N/A")
        template_name = info.get("name", template_id)
        host = item.get("host", "N/A")
        matched_at = item.get("matched-at", host)
        
        extracted = item.get("extracted-results", [])
        if isinstance(extracted, list):
            extracted = ", ".join(extracted)
        elif extracted is None:
            extracted = "-"
            
        desc = info.get("description", "No description provided.")
        
        # Helper to format code blocks
        def code_block(title, content):
            if not content: return ""
            return f'<div class="detail-row"><div class="detail-label">{title}</div><div class="detail-value"><pre>{html.escape(str(content))}</pre></div></div>'

        curl = code_block("CURL", item.get("curl-command"))
        req = code_block("Request", item.get("request"))
        resp = code_block("Response", item.get("response"))

        finding_html = Template(FINDING_TEMPLATE).safe_substitute(
            severity_lower=severity,
            severity_upper=severity.upper(),
            template_name=html.escape(template_name),
            host=html.escape(host),
            template_id=html.escape(template_id),
            matched_at=matched_at,
            extracted_results=html.escape(str(extracted)),
            description=html.escape(desc),
            curl_command=curl,
            request_block=req,
            response_block=resp
        )
        findings_html_list.append(finding_html)

    # Fill main template
    full_html = Template(HTML_TEMPLATE).safe_substitute(
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_count=len(data),
        critical_count=stats["critical"],
        high_count=stats["high"],
        medium_count=stats["medium"],
        low_count=stats["low"],
        info_count=stats["info"],
        findings_html="\n".join(findings_html_list)
    )

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_html)
        print(f"Successfully generated report at: {output_file}")
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    args = parse_args()
    data = load_data(args.input)
    if not data:
        print("No valid data found in input file.", file=sys.stderr)
        sys.exit(1)
    generate_report(data, args.output)

if __name__ == "__main__":
    main()
