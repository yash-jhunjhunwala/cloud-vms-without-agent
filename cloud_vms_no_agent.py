#!/usr/bin/env python3
"""
Cloud VMs Without Agent - Report Generator

Queries cloud security platform APIs to find cloud VMs that don't have a cloud agent installed.
Supports AWS, Azure, and GCP. Generates both CSV and HTML reports.

Author: Yash Jhunjhunwala
Version: 1.2.0
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
from html import escape

import requests
from requests.auth import HTTPBasicAuth

VERSION = "1.2.0"

# Platform configuration: gateway for Bearer auth, api for Basic auth
PLATFORMS = {
    "US1": {"gateway": "gateway.qg1.apps.qualys.com", "api": "qualysapi.qg1.apps.qualys.com"},
    "US2": {"gateway": "gateway.qg2.apps.qualys.com", "api": "qualysapi.qg2.apps.qualys.com"},
    "US3": {"gateway": "gateway.qg3.apps.qualys.com", "api": "qualysapi.qg3.apps.qualys.com"},
    "US4": {"gateway": "gateway.qg4.apps.qualys.com", "api": "qualysapi.qg4.apps.qualys.com"},
    "EU1": {"gateway": "gateway.qg1.apps.qualys.eu", "api": "qualysapi.qg1.apps.qualys.eu"},
    "EU2": {"gateway": "gateway.qg2.apps.qualys.eu", "api": "qualysapi.qg2.apps.qualys.eu"},
    "IN1": {"gateway": "gateway.qg1.apps.qualys.in", "api": "qualysapi.qg1.apps.qualys.in"},
    "CA1": {"gateway": "gateway.qg1.apps.qualys.ca", "api": "qualysapi.qg1.apps.qualys.ca"},
    "AE1": {"gateway": "gateway.qg1.apps.qualys.ae", "api": "qualysapi.qg1.apps.qualys.ae"},
    "UK1": {"gateway": "gateway.qg1.apps.qualys.co.uk", "api": "qualysapi.qg1.apps.qualys.co.uk"},
    "AU1": {"gateway": "gateway.qg1.apps.qualys.com.au", "api": "qualysapi.qg1.apps.qualys.com.au"},
}


# Tracking method to friendly source name mapping
TRACKING_SOURCES = {
    "QAGENT": "Cloud Agent",
    "INSTANCE_ID": "EC2 Connector",
    "VM_ID": "Azure Connector",
    "IP": "Scanner",
    "DNS": "Scanner",
    "NETBIOS": "Scanner",
    "EC2": "EC2 Connector",
    "GCP": "GCP Connector",
    "AZURE": "Azure Connector",
}

# Source info keys to friendly names with icons
SOURCE_INFO_MAPPING = {
    "Ec2AssetSourceSimple": ("EC2 Connector", "🔌"),
    "AzureAssetSourceSimple": ("Azure Connector", "🔌"),
    "GcpAssetSourceSimple": ("GCP Connector", "🔌"),
    "AgentAssetSource": ("Cloud Agent", "🤖"),
    "QualysAssetSource": ("Scanner", "🔍"),
    "AssetSource": None,  # Skip generic AssetSource
}


@dataclass
class CloudAsset:
    """Represents a cloud asset from Qualys."""
    asset_id: str
    name: str
    cloud_provider: str
    account_id: str
    account_alias: str = ""
    region: str = ""
    instance_id: str = ""
    instance_type: str = ""
    private_ip: str = ""
    public_ip: str = ""
    state: str = ""
    created: str = ""
    last_updated: str = ""
    source: str = ""
    tags: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "Asset ID": self.asset_id,
            "Name": self.name,
            "Cloud Provider": self.cloud_provider,
            "Account ID": self.account_id,
            "Account Alias": self.account_alias,
            "Region": self.region,
            "Instance ID": self.instance_id,
            "Instance Type": self.instance_type,
            "Private IP": self.private_ip,
            "Public IP": self.public_ip,
            "State": self.state,
            "Source": self.source,
            "Created": self.created,
            "Last Updated": self.last_updated,
            "Tags": json.dumps(self.tags) if self.tags else "",
        }


class QualysClient:
    """Client for interacting with Qualys APIs."""

    def __init__(self, username: str, password: str, platform: str):
        self.username = username
        self.password = password
        self.platform = platform.upper()
        
        if self.platform not in PLATFORMS:
            raise ValueError(f"Unknown platform: {platform}. Valid: {', '.join(PLATFORMS.keys())}")
        
        self.gateway_url = f"https://{PLATFORMS[self.platform]['gateway']}"
        self.api_url = f"https://{PLATFORMS[self.platform]['api']}"
        self.bearer_token: Optional[str] = None
        self.account_aliases: dict[str, str] = {}

    def authenticate(self) -> bool:
        """Get Bearer token from auth endpoint."""
        url = f"{self.gateway_url}/auth"
        try:
            resp = requests.post(url, data={
                "username": self.username,
                "password": self.password,
                "token": "true"
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            
            if resp.status_code in (200, 201):
                self.bearer_token = resp.text.strip()
                print(f"✓ Authenticated to {self.platform}")
                return True
            print(f"✗ Auth failed: {resp.status_code}")
            return False
        except Exception as e:
            print(f"✗ Auth error: {e}")
            return False

    def get_connectors(self, cloud_type: str = "AWS") -> list[dict]:
        """Get cloud connectors using Connector v1.0 API."""
        if not self.bearer_token:
            return []
        
        url = f"{self.gateway_url}/connectors/v1.0/{cloud_type}/list"
        try:
            resp = requests.get(url, headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Accept": "application/json"
            })
            if resp.status_code == 200:
                data = resp.json()
                connectors = data.get("content", [])
                print(f"✓ Found {len(connectors)} {cloud_type} connectors")
                return connectors
            print(f"✗ Connectors API: {resp.status_code}")
            return []
        except Exception as e:
            print(f"✗ Connectors error: {e}")
            return []

    def fetch_account_aliases(self, cloud_type: str = "AWS") -> dict[str, str]:
        """Fetch account/subscription/project aliases using multiple APIs."""
        
        # First try Connector v1.0 API (has account aliases for AWS)
        if self.bearer_token and cloud_type.upper() == "AWS":
            try:
                url = f"{self.gateway_url}/connectors/v1.0/AWS/list"
                resp = requests.get(url, headers={
                    "Authorization": f"Bearer {self.bearer_token}",
                    "Accept": "application/json"
                })
                if resp.status_code == 200:
                    data = resp.json()
                    for conn in data.get("content", []):
                        account_id = conn.get("awsAccountId", "")
                        # Try multiple fields for alias
                        alias = conn.get("accountAlias") or conn.get("name") or conn.get("description", "")
                        if account_id and alias:
                            self.account_aliases[account_id] = alias
            except Exception:
                pass
        
        # Also try v3.0 Asset Data Connector API
        api_config = {
            "AWS": {
                "endpoint": "awsassetdataconnector",
                "connector_key": "AwsAssetDataConnector",
                "id_field": "awsAccountId",
                "alias_field": "accountAlias"
            },
            "AZURE": {
                "endpoint": "azureassetdataconnector",
                "connector_key": "AzureAssetDataConnector",
                "id_field": "authRecord.subscriptionId",
                "alias_field": "name"
            },
            "GCP": {
                "endpoint": "gcpassetdataconnector",
                "connector_key": "GcpAssetDataConnector",
                "id_field": "authRecord.projectId",
                "alias_field": "name"
            }
        }
        
        config = api_config.get(cloud_type.upper())
        if not config:
            return self.account_aliases
            
        url = f"{self.api_url}/qps/rest/3.0/search/am/{config['endpoint']}"
        try:
            resp = requests.post(url, json={"ServiceRequest": {}}, auth=HTTPBasicAuth(self.username, self.password),
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                connectors = data.get("ServiceResponse", {}).get("data", [])
                for item in connectors:
                    conn = item.get(config["connector_key"], {})
                    
                    # Get ID (may be nested like authRecord.subscriptionId)
                    id_parts = config["id_field"].split(".")
                    account_id = conn
                    for part in id_parts:
                        account_id = account_id.get(part, "") if isinstance(account_id, dict) else ""
                    
                    # Get alias - try alias field first, then fall back to name
                    alias = conn.get(config["alias_field"], "") or conn.get("name", "")
                    
                    # Only add if we have an ID and alias, and don't overwrite existing
                    if account_id and alias and account_id not in self.account_aliases:
                        self.account_aliases[account_id] = alias
                        
                print(f"✓ Fetched {len(self.account_aliases)} account aliases")
            else:
                print(f"⚠ Account aliases unavailable (v3.0 API: {resp.status_code})")
        except Exception as e:
            print(f"⚠ Account aliases error: {e}")
        return self.account_aliases

    def get_assets_without_agent(self, cloud_type: str = "AWS", hours: Optional[int] = None, updated_hours: Optional[int] = None) -> list[CloudAsset]:
        """Get cloud assets without agent using Host Asset API."""
        url = f"{self.api_url}/qps/rest/2.0/search/am/hostasset"
        
        # Build filter criteria - filter by cloud type only, agent check is done client-side
        filters = [f'<Criteria field="cloudProviderType" operator="EQUALS">{cloud_type}</Criteria>']
        if hours:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            filters.append(f'<Criteria field="created" operator="GREATER">{cutoff}</Criteria>')
        if updated_hours:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=updated_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            filters.append(f'<Criteria field="updated" operator="GREATER">{cutoff}</Criteria>')

        xml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<ServiceRequest>
    <preferences><limitResults>1000</limitResults></preferences>
    <filters>{' '.join(filters)}</filters>
</ServiceRequest>"""

        assets = []
        try:
            resp = requests.post(url, data=xml_request, auth=HTTPBasicAuth(self.username, self.password),
                                 headers={"Content-Type": "application/xml", "Accept": "application/json"})
            if resp.status_code != 200:
                print(f"✗ Host Asset API: {resp.status_code}")
                return []

            data = resp.json()
            host_assets = data.get("ServiceResponse", {}).get("data", [])
            total_count = len(host_assets)
            
            for item in host_assets:
                host = item.get("HostAsset", {})
                
                # Skip assets that have an agent installed
                if host.get("agentInfo"):
                    continue
                
                # Extract cloud details from sourceInfo
                source_info = host.get("sourceInfo", {})
                source_list = source_info.get("list", []) if isinstance(source_info, dict) else []
                
                # Find cloud-specific source info
                cloud_info = {}
                tags = {}
                
                for src in source_list:
                    if "Ec2AssetSourceSimple" in src:
                        cloud_info = src["Ec2AssetSourceSimple"]
                        # Extract AWS tags
                        ec2_tags = cloud_info.get("ec2InstanceTags", {}).get("tags", {}).get("list", [])
                        for tag_item in ec2_tags:
                            if "EC2Tags" in tag_item:
                                t = tag_item["EC2Tags"]
                                tags[t.get("key", "")] = t.get("value", "")
                        break
                    elif "AzureAssetSourceSimple" in src:
                        cloud_info = src["AzureAssetSourceSimple"]
                        # Extract Azure tags
                        azure_tags = cloud_info.get("azureVmTags", {}).get("tags", {}).get("list", [])
                        for tag_item in azure_tags:
                            if "AzureTags" in tag_item:
                                t = tag_item["AzureTags"]
                                tags[t.get("key", "")] = t.get("value", "")
                        break
                    elif "GcpAssetSourceSimple" in src:
                        cloud_info = src["GcpAssetSourceSimple"]
                        # Extract GCP labels
                        gcp_labels = cloud_info.get("labels", {}).get("list", [])
                        for label_item in gcp_labels:
                            if "GcpLabels" in label_item:
                                t = label_item["GcpLabels"]
                                tags[t.get("key", "")] = t.get("value", "")
                        break
                
                # Map fields based on cloud provider
                if cloud_type.upper() == "AWS":
                    account_id = cloud_info.get("accountId", "")
                    region = cloud_info.get("region", "")
                    instance_id = cloud_info.get("instanceId", "")
                    instance_type = cloud_info.get("instanceType", "")
                    state = cloud_info.get("instanceState", "")
                elif cloud_type.upper() == "AZURE":
                    account_id = cloud_info.get("subscriptionId", "")
                    region = cloud_info.get("location", "")
                    instance_id = cloud_info.get("vmId", "")
                    instance_type = cloud_info.get("vmSize", "")
                    state = cloud_info.get("state", "")
                elif cloud_type.upper() == "GCP":
                    account_id = cloud_info.get("projectId", "")
                    region = cloud_info.get("zone", "")
                    instance_id = cloud_info.get("instanceId", "")
                    instance_type = cloud_info.get("machineType", "")
                    state = cloud_info.get("state", "")
                else:
                    account_id = region = instance_id = instance_type = state = ""
                
                # Skip terminated instances
                if state.upper() == "TERMINATED":
                    continue
                
                # Skip assets without account ID (incomplete cloud info)
                if not account_id:
                    continue
                
                # Collect all sources from sourceInfo
                sources_found = []
                for src in source_list:
                    for key in src.keys():
                        if key in SOURCE_INFO_MAPPING and SOURCE_INFO_MAPPING[key]:
                            name, icon = SOURCE_INFO_MAPPING[key]
                            if name not in [s[0] for s in sources_found]:
                                sources_found.append((name, icon))
                
                # Format sources with icons
                if sources_found:
                    source = ", ".join([f"{icon} {name}" for name, icon in sources_found])
                else:
                    # Fallback to tracking method
                    tracking_method = host.get("trackingMethod", "")
                    source = TRACKING_SOURCES.get(tracking_method, tracking_method)
                
                asset = CloudAsset(
                    asset_id=str(host.get("id", "")),
                    name=host.get("name", ""),
                    cloud_provider=host.get("cloudProvider", cloud_type),
                    account_id=account_id,
                    account_alias=self.account_aliases.get(account_id, ""),
                    region=region,
                    instance_id=instance_id,
                    instance_type=instance_type,
                    private_ip=cloud_info.get("privateIpAddress", ""),
                    public_ip=cloud_info.get("publicIpAddress", ""),
                    state=state,
                    source=source,
                    created=host.get("created", ""),
                    last_updated=host.get("modified", ""),
                    tags=tags
                )
                assets.append(asset)

            print(f"✓ Found {len(assets)} assets without agent (of {total_count} total {cloud_type} assets)")
        except Exception as e:
            print(f"✗ Assets error: {e}")
        return assets


def generate_csv_report(assets: list[CloudAsset], filename: str):
    """Generate CSV report."""
    if not assets:
        print("⚠ No assets to export to CSV")
        return
    
    headers = list(assets[0].to_dict().keys())
    with open(filename, 'w') as f:
        f.write(','.join(headers) + '\n')
        for asset in assets:
            row = asset.to_dict()
            values = [f'"{str(row[h]).replace(chr(34), chr(34)+chr(34))}"' for h in headers]
            f.write(','.join(values) + '\n')
    print(f"✓ CSV report: {filename}")


def generate_html_report(assets: list[CloudAsset], filename: str, platform: str):
    """Generate HTML report with filtering and sorting."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Group by account
    accounts = {}
    for a in assets:
        key = f"{a.account_id} ({a.account_alias})" if a.account_alias else a.account_id
        accounts[key] = accounts.get(key, 0) + 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud VMs Without Agent - Report</title>
    <style>
        :root {{
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --primary-light: #818cf8;
            --success: #10b981;
            --success-dark: #059669;
            --warning: #f59e0b;
            --danger: #ef4444;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-500: #6b7280;
            --gray-700: #374151;
            --gray-900: #111827;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: linear-gradient(135deg, var(--gray-100) 0%, var(--gray-200) 100%);
            min-height: 100vh;
            padding: 24px;
            color: var(--gray-700);
        }}
        .container {{ max-width: 1600px; margin: 0 auto; }}
        .header {{ 
            background: linear-gradient(135deg, var(--primary) 0%, #8b5cf6 50%, #a855f7 100%);
            color: white; 
            padding: 40px; 
            border-radius: 16px; 
            margin-bottom: 24px;
            box-shadow: var(--shadow-xl);
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            border-radius: 50%;
        }}
        .header::after {{
            content: '';
            position: absolute;
            bottom: -30%;
            left: 10%;
            width: 300px;
            height: 300px;
            background: radial-gradient(circle, rgba(255,255,255,0.08) 0%, transparent 70%);
            border-radius: 50%;
        }}
        .header h1 {{ 
            font-size: 32px; 
            margin-bottom: 12px; 
            font-weight: 700;
            letter-spacing: -0.5px;
            position: relative;
            z-index: 1;
        }}
        .header p {{
            opacity: 0.9;
            font-size: 14px;
            position: relative;
            z-index: 1;
        }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 24px; }}
        .stat-card {{ 
            background: white; 
            padding: 24px; 
            border-radius: 12px; 
            box-shadow: var(--shadow);
            border: 1px solid var(--gray-200);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }}
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary), var(--primary-light));
        }}
        .stat-card:nth-child(2)::before {{ background: linear-gradient(90deg, var(--success), #34d399); }}
        .stat-card:nth-child(3)::before {{ background: linear-gradient(90deg, var(--warning), #fbbf24); }}
        .stat-value {{ 
            font-size: 36px; 
            font-weight: 800; 
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            line-height: 1.2;
        }}
        .stat-card:nth-child(2) .stat-value {{
            background: linear-gradient(135deg, var(--success), #34d399);
            -webkit-background-clip: text;
            background-clip: text;
        }}
        .stat-card:nth-child(3) .stat-value {{
            background: linear-gradient(135deg, var(--warning), #fbbf24);
            -webkit-background-clip: text;
            background-clip: text;
        }}
        .stat-label {{ 
            color: var(--gray-500); 
            font-size: 13px; 
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }}
        .filters {{ 
            background: white; 
            padding: 20px 24px; 
            border-radius: 12px; 
            margin-bottom: 20px; 
            display: flex; 
            gap: 16px; 
            flex-wrap: wrap; 
            align-items: center;
            box-shadow: var(--shadow);
            border: 1px solid var(--gray-200);
        }}
        .filters input, .filters select {{ 
            padding: 12px 16px; 
            border: 2px solid var(--gray-200); 
            border-radius: 8px; 
            font-size: 14px;
            transition: all 0.2s ease;
            background: var(--gray-50);
        }}
        .filters input:focus, .filters select:focus {{
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
            background: white;
        }}
        .filters input {{ width: 320px; }}
        .filters select {{ min-width: 180px; cursor: pointer; }}
        .legend {{ 
            background: linear-gradient(135deg, #fefce8, #fef3c7);
            padding: 16px 24px; 
            border-radius: 12px; 
            margin-bottom: 20px; 
            display: flex; 
            gap: 32px; 
            flex-wrap: wrap; 
            align-items: center;
            border: 1px solid #fde68a;
        }}
        .legend-title {{ 
            font-weight: 600; 
            color: var(--gray-700);
            font-size: 14px;
        }}
        .legend-item {{ 
            display: flex; 
            align-items: center; 
            gap: 8px; 
            font-size: 13px; 
            color: var(--gray-700);
            background: white;
            padding: 6px 12px;
            border-radius: 20px;
            box-shadow: var(--shadow-sm);
        }}
        .table-container {{
            background: white;
            border-radius: 12px;
            box-shadow: var(--shadow-lg);
            border: 1px solid var(--gray-200);
            overflow: hidden;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ 
            background: linear-gradient(135deg, var(--gray-700), var(--gray-900));
            color: white; 
            padding: 16px 18px; 
            text-align: left; 
            cursor: pointer; 
            white-space: nowrap;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: background 0.2s ease;
            position: relative;
        }}
        th:hover {{ background: var(--gray-900); }}
        th::after {{
            content: '↕';
            margin-left: 6px;
            opacity: 0.4;
            font-size: 10px;
        }}
        td {{ 
            padding: 14px 18px; 
            border-bottom: 1px solid var(--gray-100); 
            font-size: 13px;
            color: var(--gray-700);
        }}
        tbody tr {{ transition: all 0.15s ease; }}
        tbody tr:hover {{ 
            background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
        }}
        tbody tr:last-child td {{ border-bottom: none; }}
        .tag {{ 
            display: inline-block; 
            background: var(--gray-100); 
            padding: 4px 10px; 
            border-radius: 6px; 
            margin: 2px; 
            font-size: 11px;
            font-weight: 500;
            color: var(--gray-700);
        }}
        .export-btn {{ 
            background: linear-gradient(135deg, var(--success), var(--success-dark));
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s ease;
            box-shadow: var(--shadow);
        }}
        .export-btn:hover {{ 
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }}
        .export-btn:active {{
            transform: translateY(0);
        }}
        .hidden {{ display: none; }}
        .state-running {{ color: var(--success); font-weight: 600; }}
        .state-stopped {{ color: var(--danger); font-weight: 600; }}
        @media (max-width: 768px) {{
            .filters input {{ width: 100%; }}
            .header {{ padding: 24px; }}
            .header h1 {{ font-size: 24px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>☁️ Cloud VMs Without Agent</h1>
            <p>Platform: {platform} | Generated: {timestamp} | Version: {VERSION}</p>
        </div>
        <div class="stats">
            <div class="stat-card"><div class="stat-value">{len(assets)}</div><div class="stat-label">Total VMs Without Agent</div></div>
            <div class="stat-card"><div class="stat-value">{len(accounts)}</div><div class="stat-label">Cloud Accounts</div></div>
            <div class="stat-card"><div class="stat-value">{len(set(a.region for a in assets))}</div><div class="stat-label">Regions</div></div>
        </div>
        <div class="legend">
            <span class="legend-title">📋 Source Legend:</span>
            <span class="legend-item">🔌 Cloud Connector</span>
            <span class="legend-item">🤖 Cloud Agent</span>
            <span class="legend-item">🔍 Scanner</span>
        </div>
        <div class="filters">
            <input type="text" id="search" placeholder="🔍 Search assets..." onkeyup="filterTable()">
            <select id="accountFilter" onchange="filterTable()">
                <option value="">All Accounts</option>
                {''.join(f'<option value="{escape(k)}">{escape(k)} ({v})</option>' for k, v in sorted(accounts.items()))}
            </select>
            <select id="regionFilter" onchange="filterTable()">
                <option value="">All Regions</option>
                {''.join(f'<option value="{escape(r)}">{escape(r)}</option>' for r in sorted(set(a.region for a in assets if a.region)))}
            </select>
            <button class="export-btn" onclick="exportVisible()">📥 Export Filtered CSV</button>
        </div>
        <div class="table-container">
        <table id="assetsTable">
            <thead><tr>
                <th onclick="sortTable(0)">Name</th>
                <th onclick="sortTable(1)">Account</th>
                <th onclick="sortTable(2)">Account Alias</th>
                <th onclick="sortTable(3)">Region</th>
                <th onclick="sortTable(4)">Instance ID</th>
                <th onclick="sortTable(5)">Type</th>
                <th onclick="sortTable(6)">Private IP</th>
                <th onclick="sortTable(7)">State</th>
                <th onclick="sortTable(8)">Source</th>
                <th onclick="sortTable(9)">Created</th>
                <th onclick="sortTable(10)">Last Updated</th>
            </tr></thead>
            <tbody>
"""
    for a in assets:
        state_class = 'state-running' if a.state.upper() == 'RUNNING' else 'state-stopped' if a.state.upper() in ('STOPPED', 'TERMINATED', 'DEALLOCATED') else ''
        html += f"""<tr data-account="{escape(a.account_id)}" data-alias="{escape(a.account_alias)}">
    <td>{escape(a.name)}</td>
    <td>{escape(a.account_id)}</td>
    <td>{escape(a.account_alias)}</td>
    <td>{escape(a.region)}</td>
    <td>{escape(a.instance_id)}</td>
    <td>{escape(a.instance_type)}</td>
    <td>{escape(a.private_ip)}</td>
    <td class="{state_class}">{escape(a.state)}</td>
    <td>{escape(a.source)}</td>
    <td>{escape(a.created[:10] if a.created else '')}</td>
    <td>{escape(a.last_updated[:10] if a.last_updated else '')}</td>
</tr>
"""

    html += """</tbody></table></div></div>
<script>
function filterTable() {
    const search = document.getElementById('search').value.toLowerCase();
    const account = document.getElementById('accountFilter').value;
    const region = document.getElementById('regionFilter').value;
    document.querySelectorAll('#assetsTable tbody tr').forEach(row => {
        const text = row.textContent.toLowerCase();
        const rowAccount = row.dataset.account + ' (' + row.dataset.alias + ')';
        const rowRegion = row.cells[3].textContent;
        const matchSearch = !search || text.includes(search);
        const matchAccount = !account || rowAccount === account || row.dataset.account === account;
        const matchRegion = !region || rowRegion === region;
        row.classList.toggle('hidden', !(matchSearch && matchAccount && matchRegion));
    });
}
let sortDir = 1;
function sortTable(col) {
    const tbody = document.querySelector('#assetsTable tbody');
    const rows = Array.from(tbody.rows);
    rows.sort((a, b) => a.cells[col].textContent.localeCompare(b.cells[col].textContent) * sortDir);
    rows.forEach(r => tbody.appendChild(r));
    sortDir *= -1;
}
function exportVisible() {
    const headers = ['Name','Account','Account Alias','Region','Instance ID','Type','Private IP','State','Source','Created'];
    let csv = headers.join(',') + '\\n';
    document.querySelectorAll('#assetsTable tbody tr:not(.hidden)').forEach(row => {
        csv += Array.from(row.cells).map(c => '"' + c.textContent.replace(/"/g, '""') + '"').join(',') + '\\n';
    });
    const blob = new Blob([csv], {type: 'text/csv'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'filtered_assets.csv';
    a.click();
}
</script>
</body></html>"""

    with open(filename, 'w') as f:
        f.write(html)
    print(f"✓ HTML report: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Find cloud VMs without Cloud Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s -u USER -p PASS -P US2
  %(prog)s -u USER -p PASS -P CA1 --hours 24
  %(prog)s -u USER -p PASS -P EU1 --cloud AZURE

Version: {VERSION}
""")
    parser.add_argument("-u", "--username", required=True, help="Qualys username")
    parser.add_argument("-p", "--password", required=True, help="Qualys password")
    parser.add_argument("-P", "--platform", required=True, choices=list(PLATFORMS.keys()), help="Qualys platform")
    parser.add_argument("-c", "--cloud", default="AWS", choices=["AWS", "AZURE", "GCP"], help="Cloud provider")
    parser.add_argument("--hours", type=int, help="Only include assets created in last N hours")
    parser.add_argument("--updated-hours", type=int, help="Only include assets updated in last N hours")
    parser.add_argument("--account-map", help="JSON file mapping account IDs to aliases")
    parser.add_argument("-o", "--output", default="cloud_vms_no_agent_report", help="Output filename prefix")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f" Cloud VMs Without Agent Report - v{VERSION}")
    print(f"{'='*60}\n")

    # Initialize client
    client = QualysClient(args.username, args.password, args.platform)

    # Authenticate
    if not client.authenticate():
        print("\n✗ Authentication failed")
        sys.exit(1)

    # Fetch account aliases
    if args.account_map:
        try:
            with open(args.account_map) as f:
                client.account_aliases = json.load(f)
            print(f"✓ Loaded {len(client.account_aliases)} aliases from file")
        except Exception as e:
            print(f"⚠ Could not load account map: {e}")
    
    # Fetch aliases for the selected cloud provider
    client.fetch_account_aliases(args.cloud)

    # Get connectors (for info)
    client.get_connectors(args.cloud)

    # Get assets without agent
    assets = client.get_assets_without_agent(args.cloud, args.hours, args.updated_hours)

    if not assets:
        print("\n✓ No cloud VMs found without agent!")
        sys.exit(0)

    # Generate both reports
    print(f"\n{'='*60}")
    print(" Generating Reports")
    print(f"{'='*60}\n")
    
    generate_csv_report(assets, f"{args.output}.csv")
    generate_html_report(assets, f"{args.output}.html", args.platform)

    print(f"\n{'='*60}")
    print(f" Summary: {len(assets)} VMs without agent")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
