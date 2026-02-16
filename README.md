# Nuclei JSON to HTML Converter

A standalone Python script to convert [Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scan results (JSON/JSONL) into a modern, interactive HTML report.

## Features

- **Zero Dependencies**: Uses only Python standard library (no `pip install` required).
- **Universal Input**: Supports both JSON Lines (default Nuclei output) and standard JSON arrays.
- **Interactive Dashboard**:
  - Filter findings by severity (Critical, High, Medium, Low, Info).
  - Search by host, template name, or description.
- **Detailed Views**: Expandable sections showing Request, Response, CURL commands, and Metadata.
- **Dark Mode UI**: Clean, professional dark-themed interface.

## Usage

### Prerequisites
- Python 3.6+

### Running the Script

```bash
python3 nuclei_to_html.py -i <input_file> -o <output_file.html>
```

### Example

1. Run Nuclei and save output as JSON:
   ```bash
   nuclei -u https://example.com -json -o nuclei_results.json
   ```

2. Convert to HTML:
   ```bash
   python3 nuclei_to_html.py -i nuclei_results.json -o report.html
   ```

3. Open `report.html` in your browser.

## Screenshots

*(You can add screenshots here)*

## License

MIT
