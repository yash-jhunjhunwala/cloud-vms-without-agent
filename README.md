# Cloud VMs Without Agent

A Python CLI tool to identify cloud virtual machines that don't have a cloud security agent installed. Supports AWS, Azure, and GCP. Generates interactive HTML and CSV reports.

## Features

- **Multi-Cloud Support**: AWS, Azure, and GCP
- **Multi-Platform**: Works with all supported API platforms (US1-4, EU1-2, CA1, IN1, AE1, UK1, AU1)
- **Account Aliases**: Automatically fetches friendly names for AWS accounts, Azure subscriptions, and GCP projects
- **Time Filtering**: Filter by creation date or last updated date
- **Source Tracking**: Shows how each asset was discovered (Connector, Agent, Scanner)
- **Interactive HTML Report**: 
  - Search across all fields
  - Filter by account/region
  - Sortable columns
  - Export filtered data to CSV
  - Modern, responsive UI
- **CSV Export**: Full data export for spreadsheet analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/yash-jhunjhunwala/cloud-vms-without-agent.git
cd cloud-vms-without-agent

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage - finds all AWS VMs without agent
python cloud_vms_no_agent.py -u USERNAME -p PASSWORD -e PLATFORM

# Azure VMs without agent
python cloud_vms_no_agent.py -u USERNAME -p PASSWORD -e US2 -c AZURE

# GCP VMs without agent  
python cloud_vms_no_agent.py -u USERNAME -p PASSWORD -e EU1 -c GCP

# Filter by last updated time (e.g., last 24 hours)
python cloud_vms_no_agent.py -u USERNAME -p PASSWORD -e CA1 --updated-hours 24

# Filter by creation time (e.g., last 7 days)
python cloud_vms_no_agent.py -u USERNAME -p PASSWORD -e US1 --hours 168

# Custom output filename
python cloud_vms_no_agent.py -u USERNAME -p PASSWORD -e US2 -o my_report
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-u, --username` | API username (required) |
| `-p, --password` | API password (required) |
| `-e, --platform` | API platform/endpoint: US1-4, EU1-2, CA1, IN1, AE1, UK1, AU1 (required) |
| `-c, --cloud` | Cloud provider: AWS, AZURE, GCP (default: AWS) |
| `--hours` | Only include assets created in the last N hours |
| `--updated-hours` | Only include assets updated in the last N hours |
| `--account-map` | JSON file mapping account IDs to custom aliases |
| `-o, --output` | Output filename prefix (default: cloud_vms_no_agent_report) |
| `-v, --version` | Show version number |

## Output

The tool generates two report files:

### CSV Report (`cloud_vms_no_agent_report.csv`)
Contains all asset details in spreadsheet format:
- Asset ID, Name, Cloud Provider
- Account ID, Account Alias
- Region, Instance ID, Instance Type
- Private IP, Public IP, State
- Source (how discovered)
- Created date, Last Updated date
- Tags

### HTML Report (`cloud_vms_no_agent_report.html`)
Interactive web report with:
- Summary statistics (total VMs, accounts, regions)
- Search box for filtering
- Dropdown filters for account and region
- Sortable table columns
- Export filtered results to CSV
- Source legend with icons

## Important Notes

### Filtered Assets
The tool automatically filters out:
- **Assets with agent installed** - Only shows VMs without the cloud agent
- **Terminated instances** - Skips VMs in TERMINATED state
- **Assets without Account ID** - Skips assets with incomplete cloud info (see below)

### Why Account ID Might Be Missing
Some assets may not have an Account ID when:
- The asset was discovered by a **scanner** but not linked to a cloud connector
- The cloud connector hasn't synced the asset's metadata yet
- The asset exists in the platform but the **cloud source info is incomplete**

These assets are excluded from the report since they can't be properly attributed to a cloud account.

### Count Differences
You may notice the report shows fewer accounts than your total cloud accounts:
- The report only counts accounts that have **VMs without agent**
- Accounts where all VMs have agents installed won't appear
- Accounts with only terminated instances won't appear

## Account Alias Mapping

The tool automatically fetches account aliases from the API. You can also provide custom mappings:

```bash
python cloud_vms_no_agent.py -u USER -p PASS -e US2 --account-map accounts.json
```

Example `accounts.json`:
```json
{
    "123456789012": "Production",
    "234567890123": "Development",
    "345678901234": "Staging"
}
```

## Supported Platforms

| Platform | Region |
|----------|--------|
| US1 | United States |
| US2 | United States |
| US3 | United States |
| US4 | United States |
| EU1 | Europe |
| EU2 | Europe |
| CA1 | Canada |
| IN1 | India |
| AE1 | UAE |
| UK1 | United Kingdom |
| AU1 | Australia |

## Examples

### Find AWS VMs without agent updated in the last 24 hours
```bash
python cloud_vms_no_agent.py -u myuser -p 'mypass' -e US2 -c AWS --updated-hours 24
```

### Find all Azure VMs without agent
```bash
python cloud_vms_no_agent.py -u myuser -p 'mypass' -e EU1 -c AZURE
```

### Find GCP VMs created in the last 7 days
```bash
python cloud_vms_no_agent.py -u myuser -p 'mypass' -e CA1 -c GCP --hours 168
```

## Requirements

- Python 3.9+
- requests

## License

MIT License

## Author

Yash Jhunjhunwala

## Version

1.2.0
