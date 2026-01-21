"""
TwinSanity Recon V2 - Wordlist Manager
======================================
Manages wordlists for brute force subdomain discovery.
Includes built-in wordlists and custom wordlist support.
"""

import logging
from pathlib import Path
from typing import List, Optional, Dict, Generator
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# Directory for wordlists
WORDLIST_DIR = Path(__file__).parent.parent / "wordlists"


class WordlistSize(Enum):
    TINY = "tiny"        # ~100 entries - Quick test
    SMALL = "small"      # ~1000 entries - Fast scan
    MEDIUM = "medium"    # ~5000 entries - Balanced
    LARGE = "large"      # ~20000 entries - Thorough
    HUGE = "huge"        # ~100000 entries - Comprehensive


@dataclass
class WordlistInfo:
    """Information about a wordlist"""
    name: str
    size: WordlistSize
    path: Optional[Path]
    entry_count: int
    description: str
    is_builtin: bool = True


# Built-in subdomain wordlists
BUILTIN_WORDLISTS = {
    "tiny": WordlistInfo(
        name="Tiny (Quick Test)",
        size=WordlistSize.TINY,
        path=None,  # Generated inline
        entry_count=100,
        description="100 most common subdomains for quick testing"
    ),
    "small": WordlistInfo(
        name="Small (Fast)",
        size=WordlistSize.SMALL,
        path=None,
        entry_count=1000,
        description="1,000 common subdomains for fast scans"
    ),
    "medium": WordlistInfo(
        name="Medium (Balanced)",
        size=WordlistSize.MEDIUM,
        path=None,
        entry_count=5000,
        description="5,000 subdomains for balanced coverage"
    ),
    "large": WordlistInfo(
        name="Large (Thorough)",
        size=WordlistSize.LARGE,
        path=None,
        entry_count=20000,
        description="20,000 subdomains for thorough scanning"
    )
}

# Top subdomains (used to generate built-in lists)
TOP_SUBDOMAINS = [
    # Critical/Common (Top 100)
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "remote", "blog", "webdisk", "server",
    "cpanel", "whm", "autodiscover", "autoconfig", "api", "dev", "staging", "test",
    "admin", "administrator", "app", "apps", "portal", "secure", "vpn", "ssl", "web",
    "www2", "www3", "old", "new", "mobile", "m", "shop", "store", "forum", "forums",
    "wiki", "support", "help", "docs", "doc", "kb", "faq", "status", "stats", "static",
    "assets", "cdn", "media", "images", "img", "video", "files", "download", "downloads",
    "upload", "uploads", "backup", "db", "database", "mysql", "sql", "oracle", "mongo",
    "redis", "cache", "proxy", "gateway", "firewall", "router", "switch", "lb", "load",
    "node", "node1", "node2", "cluster", "master", "slave", "primary", "secondary",
    "demo", "beta", "alpha", "stage", "uat", "qa", "prod", "production", "live",
    "internal", "intranet", "extranet", "private", "public", "corp", "corporate",
    
    # Extended (100-500)
    "email", "e-mail", "exchange", "outlook", "office", "o365", "calendar", "cal",
    "chat", "im", "irc", "slack", "teams", "meet", "zoom", "conference", "video",
    "crm", "erp", "sap", "salesforce", "hubspot", "marketing", "sales", "hr", "finance",
    "accounting", "billing", "payment", "payments", "pay", "checkout", "cart", "order",
    "orders", "invoice", "invoices", "ticket", "tickets", "issue", "issues", "jira",
    "jenkins", "ci", "cd", "build", "deploy", "release", "git", "gitlab", "github",
    "bitbucket", "svn", "repo", "repository", "code", "source", "src", "dev1", "dev2",
    "test1", "test2", "test3", "staging1", "staging2", "uat1", "uat2", "prod1", "prod2",
    "web1", "web2", "web3", "app1", "app2", "app3", "server1", "server2", "server3",
    "host", "host1", "host2", "vps", "vps1", "vps2", "cloud", "aws", "azure", "gcp",
    "digitalocean", "linode", "vultr", "heroku", "docker", "k8s", "kubernetes", "rancher",
    "monitoring", "monitor", "grafana", "prometheus", "nagios", "zabbix", "datadog",
    "elk", "elasticsearch", "kibana", "logstash", "splunk", "log", "logs", "logging",
    "analytics", "ga", "gtm", "pixel", "track", "tracking", "metrics", "metric",
    "report", "reports", "reporting", "dashboard", "panel", "console", "control",
    "manager", "management", "manage", "config", "configuration", "settings", "setup",
    "install", "installer", "update", "updates", "upgrade", "patch", "hotfix", "fix",
    "auth", "authentication", "authorize", "authorization", "login", "logout", "signin",
    "signup", "register", "registration", "account", "accounts", "user", "users",
    "profile", "profiles", "member", "members", "customer", "customers", "client",
    "clients", "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
    "employee", "employees", "staff", "team", "people", "directory", "ldap", "ad",
    "sso", "saml", "oauth", "openid", "identity", "idp", "iam", "access", "permission",
    "role", "roles", "group", "groups", "policy", "policies", "audit", "compliance",
    "security", "sec", "infosec", "cybersec", "soc", "noc", "ops", "devops", "sre",
    "network", "net", "lan", "wan", "wifi", "wireless", "wlan", "ethernet", "fiber",
    "storage", "nas", "san", "backup1", "backup2", "dr", "disaster", "recovery",
    "archive", "archives", "history", "legacy", "deprecated", "retired", "eol",
    
    # Services (500-1000)
    "api1", "api2", "api3", "rest", "restapi", "graphql", "soap", "wsdl", "rpc", "grpc",
    "ws", "websocket", "socket", "realtime", "rt", "stream", "streaming", "feed", "rss",
    "atom", "json", "xml", "csv", "data", "dataset", "datasets", "open", "opendata",
    "public-api", "developer", "developers", "dev-api", "sandbox", "playground",
    "docs-api", "api-docs", "swagger", "openapi", "postman", "insomnia", "curl",
    "health", "healthcheck", "heartbeat", "ping", "alive", "ready", "readiness",
    "liveness", "probe", "check", "verify", "validate", "validation", "test-api",
    "v1", "v2", "v3", "version", "latest", "stable", "edge", "canary", "preview",
    "experiment", "experimental", "feature", "features", "flag", "flags", "toggle",
    "a", "b", "c", "ab", "abtesting", "variant", "variants", "segment", "segments",
    "event", "events", "webhook", "webhooks", "callback", "callbacks", "notify",
    "notification", "notifications", "alert", "alerts", "alarm", "alarms", "warning",
    "error", "errors", "exception", "exceptions", "crash", "crashes", "bug", "bugs",
    "debug", "debugger", "trace", "tracing", "span", "spans", "context", "correlation",
    "request", "requests", "response", "responses", "header", "headers", "body",
    "payload", "message", "messages", "queue", "queues", "mq", "rabbitmq", "kafka",
    "sqs", "sns", "pubsub", "pub", "sub", "subscribe", "subscription", "subscriptions",
    "publish", "publisher", "consumer", "consumers", "producer", "producers", "worker",
    "workers", "job", "jobs", "task", "tasks", "scheduler", "schedule", "cron", "batch",
    "async", "sync", "parallel", "concurrent", "thread", "threads", "process", "processes",
    
    # Geographic/Regional
    "us", "usa", "america", "na", "eu", "europe", "uk", "gb", "de", "fr", "es", "it",
    "nl", "be", "ch", "at", "pl", "cz", "ru", "asia", "ap", "apac", "jp", "japan",
    "cn", "china", "kr", "korea", "in", "india", "au", "australia", "nz", "br", "brazil",
    "mx", "mexico", "ca", "canada", "latam", "emea", "mena", "gcc", "uae", "sa", "ae",
    "east", "west", "north", "south", "central", "region1", "region2", "zone1", "zone2",
    "dc1", "dc2", "datacenter", "datacenter1", "datacenter2", "colo", "colocation",
    
    # Numeric patterns
    "1", "2", "3", "4", "5", "01", "02", "03", "04", "05", "001", "002", "003",
    "a1", "a2", "b1", "b2", "c1", "c2", "x1", "x2", "y1", "y2", "z1", "z2",
]


class WordlistManager:
    """Manages wordlists for subdomain brute forcing"""
    
    def __init__(self):
        self.custom_wordlists: Dict[str, Path] = {}
        self._ensure_wordlist_dir()
    
    def _ensure_wordlist_dir(self):
        """Create wordlist directory if it doesn't exist"""
        WORDLIST_DIR.mkdir(parents=True, exist_ok=True)
    
    def get_available_wordlists(self) -> List[Dict]:
        """Get list of all available wordlists"""
        wordlists = []
        
        # Add built-in wordlists
        for key, info in BUILTIN_WORDLISTS.items():
            wordlists.append({
                "id": key,
                "name": info.name,
                "size": info.size.value,
                "entry_count": info.entry_count,
                "description": info.description,
                "is_builtin": True
            })
        
        # Add custom wordlists from directory
        for wl_file in WORDLIST_DIR.glob("*.txt"):
            line_count = sum(1 for _ in open(wl_file, 'r', errors='ignore'))
            wordlists.append({
                "id": f"custom:{wl_file.stem}",
                "name": wl_file.stem,
                "size": "custom",
                "entry_count": line_count,
                "description": f"Custom wordlist: {wl_file.name}",
                "is_builtin": False,
                "path": str(wl_file)
            })
        
        return wordlists
    
    def get_wordlist_entries(self, wordlist_id: str) -> Generator[str, None, None]:
        """
        Get entries from a wordlist as a generator.
        Yields subdomain prefixes one at a time.
        """
        if wordlist_id.startswith("custom:"):
            # Load custom wordlist from file
            filename = wordlist_id.replace("custom:", "")
            filepath = WORDLIST_DIR / f"{filename}.txt"
            if filepath.exists():
                with open(filepath, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith('#'):
                            yield line
            return
        
        # Built-in wordlists
        if wordlist_id == "tiny":
            for entry in TOP_SUBDOMAINS[:100]:
                yield entry
        
        elif wordlist_id == "small":
            for entry in TOP_SUBDOMAINS[:500]:
                yield entry
            # Add some numeric variations
            for prefix in ["www", "mail", "ns", "mx", "web", "app", "api", "dev", "test"]:
                for i in range(1, 11):
                    yield f"{prefix}{i}"
        
        elif wordlist_id == "medium":
            # All defined subdomains
            for entry in TOP_SUBDOMAINS:
                yield entry
            # Add variations
            for prefix in TOP_SUBDOMAINS[:100]:
                for i in range(1, 6):
                    yield f"{prefix}{i}"
                yield f"{prefix}-dev"
                yield f"{prefix}-test"
                yield f"{prefix}-staging"
                yield f"{prefix}-prod"
        
        elif wordlist_id == "large":
            # All defined subdomains
            for entry in TOP_SUBDOMAINS:
                yield entry
            # Extensive variations
            for prefix in TOP_SUBDOMAINS[:200]:
                for i in range(1, 21):
                    yield f"{prefix}{i}"
                for suffix in ["dev", "test", "staging", "prod", "api", "admin", "internal", "external", "old", "new", "backup"]:
                    yield f"{prefix}-{suffix}"
                    yield f"{suffix}-{prefix}"
            # Common patterns
            for letter in "abcdefghijklmnopqrstuvwxyz":
                yield letter
                yield f"{letter}1"
                yield f"{letter}2"
                for num in range(1, 100):
                    yield f"{letter}{num}"
    
    def get_wordlist_count(self, wordlist_id: str) -> int:
        """Get approximate entry count for a wordlist"""
        if wordlist_id in BUILTIN_WORDLISTS:
            return BUILTIN_WORDLISTS[wordlist_id].entry_count
        
        if wordlist_id.startswith("custom:"):
            filename = wordlist_id.replace("custom:", "")
            filepath = WORDLIST_DIR / f"{filename}.txt"
            if filepath.exists():
                return sum(1 for _ in open(filepath, 'r', errors='ignore'))
        
        return 0
    
    def save_custom_wordlist(self, name: str, content: str) -> Dict:
        """
        Save a custom wordlist.
        Returns info about the saved wordlist.
        """
        # Sanitize filename
        safe_name = "".join(c for c in name if c.isalnum() or c in "._-").strip()
        if not safe_name:
            safe_name = "custom_wordlist"
        
        filepath = WORDLIST_DIR / f"{safe_name}.txt"
        
        # Process and deduplicate entries
        entries = set()
        for line in content.strip().split('\n'):
            line = line.strip().lower()
            if line and not line.startswith('#'):
                # Remove any domain suffix if present
                line = line.split('.')[0]
                entries.add(line)
        
        # Sort and save
        sorted_entries = sorted(entries)
        filepath.write_text('\n'.join(sorted_entries), encoding='utf-8')
        
        return {
            "id": f"custom:{safe_name}",
            "name": safe_name,
            "path": str(filepath),
            "entry_count": len(sorted_entries),
            "message": f"Saved {len(sorted_entries)} unique entries to {filepath.name}"
        }
    
    def delete_custom_wordlist(self, wordlist_id: str) -> bool:
        """Delete a custom wordlist"""
        if not wordlist_id.startswith("custom:"):
            return False
        
        filename = wordlist_id.replace("custom:", "")
        filepath = WORDLIST_DIR / f"{filename}.txt"
        
        if filepath.exists():
            filepath.unlink()
            return True
        return False


# Global wordlist manager instance
wordlist_manager = WordlistManager()


def get_wordlist_manager() -> WordlistManager:
    """Get the global wordlist manager instance"""
    return wordlist_manager
