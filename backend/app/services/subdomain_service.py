"""
Subdomain Enumeration Service — Shadow Spike
Multi-source subdomain discovery:
  1. DNS Brute-force (large wordlist)
  2. Certificate Transparency (crt.sh)
  3. HackerTarget API
  4. AlienVault OTX API
  5. HTTP probing for live hosts
"""
import asyncio
import dns.resolver
import httpx
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

# ─── WORDLISTS ──────────────────────────────────────────────────────────────
# Comprehensive subdomain wordlist (curated from SecLists + common patterns)

BASE_WORDS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "staging", "test",
    "api", "app", "cdn", "cloud", "cpanel", "dashboard", "db", "demo",
    "docs", "email", "gateway", "git", "grafana", "help", "host",
    "jenkins", "jira", "kb", "login", "m", "manage", "monitor",
    "mx", "mysql", "ns1", "ns2", "panel", "portal", "proxy",
    "remote", "secure", "server", "shop", "smtp", "sql", "ssh",
    "ssl", "stage", "status", "store", "support", "vpn", "web",
    "webmail", "wiki", "www2", "alpha", "analytics", "archive", "assets",
    "auth", "autodiscover", "backup", "beta", "billing", "board",
    "cache", "calendar", "chat", "ci", "client", "cms", "community",
    "conf", "config", "connect", "console", "contact", "core", "corp",
    "crm", "css", "data", "deploy", "design", "development", "dir",
    "dl", "dns", "dns1", "dns2", "download", "edge", "elastic", "erp",
    "events", "exchange", "ext", "feed", "file", "files", "firewall",
    "forum", "ftp2", "games", "gw", "home", "hr", "hub", "id", "img",
    "images", "imap", "info", "internal", "intranet", "irc", "it",
    "jobs", "lab", "labs", "ldap", "legacy", "library", "link", "links",
    "list", "live", "local", "log", "logs", "lyncdiscover", "mail2",
    "mailhost", "marketing", "media", "meet", "meeting", "member",
    "members", "messaging", "mgmt", "mobile", "monitoring", "mq",
    "msg", "mx1", "mx2", "nas", "net", "network", "new", "news",
    "node", "ns", "ns3", "ns4", "office", "old", "ops", "order",
    "origin", "outlook", "owa", "payment", "pbx", "photo", "photos",
    "pilot", "platform", "pm", "pop", "pop3", "preview", "print",
    "prod", "production", "projects", "qa", "queue", "radio",
    "rdp", "redirect", "redis", "relay", "report", "reports",
    "repo", "resources", "rest", "review", "root", "router",
    "rss", "rt", "s", "s1", "s2", "s3", "sandbox", "search",
    "security", "service", "services", "share", "sip", "site",
    "sms", "social", "solr", "source", "spark", "staff", "stat",
    "static", "stats", "storage", "stream", "sv", "svn", "sync",
    "sys", "system", "task", "tasks", "team", "tech", "testing",
    "ticket", "tickets", "time", "tools", "track", "tracker",
    "training", "ts", "tunnel", "up", "update", "upload", "v",
    "v1", "v2", "vault", "video", "vip", "vm", "voip", "w",
    "wap", "web1", "web2", "webapp", "webdisk", "weblog", "webproxy",
    "ww", "www1", "www3", "xml", "xmpp", "zabbix",
]

EXTENDED_WORDS = [
    "about", "abuse", "access", "account", "accounts", "activate", "ad",
    "adm", "ads", "adult", "adwords", "affiliate", "affiliates", "ajax",
    "alert", "alerts", "alias", "aliases", "analog", "antispam", "api2",
    "api3", "apis", "ar", "asterisk", "auth2", "autoconfig", "av", "b",
    "b2b", "back", "backend", "backoffice", "backups", "badge", "bank",
    "banner", "bastion", "batch", "bb", "bbs", "bg", "bigip", "bind",
    "blackboard", "blog2", "blogs", "bm", "bn", "bo", "book", "booking",
    "box", "br", "brand", "bridge", "broadband", "broker", "bt", "bug",
    "bugtracker", "bugs", "build", "builder", "bulk", "business", "buy",
    "c", "ca", "cam", "campaign", "campaigns", "canvas", "careers",
    "cart", "catalog", "cdn1", "cdn2", "cdn3", "central", "cert",
    "certs", "cg", "channel", "checkout", "chef", "citrix", "cl",
    "class", "classroom", "click", "clients", "cloud1", "cloud2",
    "cluster", "cn", "co", "code", "collab", "collaboration", "comm",
    "commerce", "communication", "communications", "compare", "compras",
    "compute", "confluence", "content", "control", "controller",
    "controlpanel", "convert", "cookie", "cp", "crl", "crowd", "cs",
    "ct", "custom", "customer", "customers", "cx", "d", "daemon",
    "dat", "database", "datacenter", "de", "deal", "deals", "debug",
    "default", "delivery", "demo1", "demo2", "demos", "department",
    "desk", "detect", "dev1", "dev2", "dev3", "devel", "developer",
    "developers", "devops", "df", "di", "dial", "digital", "direct",
    "directory", "discover", "discovery", "discuss", "discussion",
    "disk", "display", "dist", "distribution", "dj", "dk", "dm",
    "doc", "docker", "domain", "domains", "donate", "down",
    "drive", "drm", "drop", "ds", "dyn", "dynamic", "e", "ecom",
    "ecommerce", "edu", "education", "ehr", "ems", "en", "eng",
    "engine", "enterprise", "env", "es", "eu", "exam", "example",
    "exec", "export", "express", "extl", "extra", "extranet", "f",
    "f5", "facebook", "failover", "faq", "fas", "fast", "fax",
    "fb", "feedback", "fi", "fileserver", "fin", "finance", "fix",
    "flash", "flow", "fm", "follow", "foo", "forms", "foundation",
    "fox", "fr", "free", "front", "frontend", "fs", "ft", "ftp1",
    "ftp3", "ftps", "fun", "fw", "g", "ga", "gallery", "gc",
    "gg", "gh", "github", "gl", "global", "gm", "go", "google",
    "gov", "gp", "gpu", "gr", "graph", "green", "group", "groups",
    "gs", "guide", "h", "ha", "hack", "handle", "hardware", "hb",
    "hd", "health", "hello", "helpdesk", "hermes", "hg", "hidden",
    "hipaa", "hk", "hm", "hold", "horizon", "hotfix", "hp", "hs",
    "http", "https", "i", "iam", "ice", "ie", "ilo", "im",
    "image", "import", "in", "include", "incoming", "index",
    "india", "infra", "infrastructure", "inside", "install",
    "integration", "intern", "inventory", "io", "ip", "ipa",
    "ipam", "iphone", "ipsec", "ipv4", "ipv6", "ir", "is", "iscsi",
    "issue", "issues", "j", "ja", "java", "jboss", "je", "jm",
    "job", "join", "jp", "js", "json", "jump", "k", "k8s",
    "kafka", "kb2", "keep", "kerberos", "key", "keys", "kibana",
    "km", "knowledge", "kong", "kr", "kubernetes", "l", "la",
    "lamp", "lan", "landing", "launch", "lb", "lc", "learn",
    "learning", "lib", "license", "line", "linux", "listing",
    "lk", "ll", "lms", "loadbalancer", "locale", "localhost",
    "location", "lock", "logging", "loghost", "lp", "lt", "lu",
    "m1", "m2", "mac", "magento", "mailgw", "main", "maintenance",
    "mall", "manager", "manifest", "map", "maps", "master",
    "matrix", "mc", "md", "mdm", "me", "memo", "merchant",
    "mercury", "mesh", "meta", "metrics", "mg", "micro", "mirror",
    "mis", "mk", "ml", "mm", "mn", "mo", "mock", "mod", "models",
    "money", "mongodb", "ms", "mssql", "mt", "mta", "mu", "mw",
    "mx3", "mx4", "mx5", "my", "myaccount", "myadmin", "n", "na",
    "name", "nameserver", "nat", "nb", "nc", "nd", "nds", "ng",
    "nginx", "ni", "nl", "nms", "no", "noc", "np", "ns5", "ns6",
    "ns7", "ns8", "nt", "ntp", "ntp1", "ntp2", "nu", "nz", "o",
    "oa", "oauth", "oc", "offer", "offers", "ok", "one", "online",
    "open", "openid", "opensource", "operations", "opt", "oracle",
    "orange", "oss", "ost", "outbound", "p", "packages", "pad",
    "page", "pages", "pam", "pan", "partner", "partners", "pass",
    "password", "patch", "pay", "pc", "pda", "pdf", "pe", "pen",
    "people", "perf", "performance", "pg", "ph", "phone", "pi",
    "pic", "pics", "ping", "pipelines", "pk", "pl", "play",
    "player", "plm", "plugin", "plus", "pma", "pms", "po", "poc",
    "podcast", "point", "policy", "poll", "pool", "pop3s", "port",
    "post", "postgres", "postgresql", "postman", "power", "pp",
    "ppc", "pr", "preprod", "press", "private", "pro", "probe",
    "process", "product", "products", "profile", "profiles",
    "program", "project", "promo", "promotion", "protect",
    "provision", "proxy2", "ps", "pt", "pub", "public",
    "purchase", "push", "px", "py", "q", "r", "rabbit",
    "rabbitmq", "ras", "raw", "rc", "rd", "rds", "re",
    "read", "realm", "rec", "record", "recovery", "ref",
    "reg", "register", "registration", "release", "releases",
    "render", "replication", "request", "research", "reserve",
    "resolver", "retail", "reverseproxy", "rf", "rm", "ro",
    "robot", "robots", "roundcube", "route", "rs", "ru",
    "run", "runner", "rw", "rx", "sa", "safe", "sales",
    "sample", "sc", "scan", "schedule", "scheduler", "schema",
    "science", "script", "scripts", "sd", "se", "sec",
    "secret", "seed", "self", "send", "sentry", "seo",
    "server1", "server2", "server3", "setup", "sf", "sftp",
    "sg", "sh", "shared", "shell", "shift", "si", "sign",
    "signal", "signup", "sim", "single", "sit", "sk", "sl",
    "slack", "slave", "sm", "smart", "sn", "snapshot", "so",
    "soap", "socket", "software", "sonar", "sp", "space",
    "spam", "spec", "speed", "splunk", "sports", "sq", "sr",
    "srs", "ss", "sso", "st", "stack", "staff2", "staging2",
    "star", "start", "static1", "static2", "stg", "stock",
    "stun", "su", "sub", "submit", "subscribe", "sudo",
    "suite", "summary", "super", "supply", "survey", "sv2",
    "svn2", "sw", "swift", "switch", "sx", "sy", "sysadmin",
    "syslog", "sz", "t", "tag", "tail", "talk", "tap",
    "target", "tax", "tb", "tc", "td", "telecom", "temp",
    "template", "tenant", "terminal", "tf", "tg", "th",
    "theme", "ticket2", "tld", "tm", "tn", "to", "token",
    "tomcat", "tp", "tr", "trace", "trade", "traffic",
    "translate", "trial", "trust", "tt", "turn", "tv",
    "tw", "tx", "txt", "tz", "u", "ua", "uat", "ug",
    "ui", "uk", "um", "ums", "uni", "union", "unit",
    "unix", "unknown", "us", "user", "users", "ut",
    "util", "utils", "ux", "uz", "v3", "v4", "va",
    "vagrant", "validate", "vc", "ve", "vendor", "verify",
    "vg", "vi", "virtual", "visa", "visual", "vn", "vo",
    "voicemail", "vps", "vr", "vs", "vu", "w1", "w2",
    "w3", "wa", "waf", "war", "watch", "wc", "weather",
    "webapi", "webcam", "webconf", "webhook", "webinar",
    "webmaster", "webmin", "webserver", "website", "webstore",
    "whm", "whois", "widget", "win", "windows", "wireless",
    "wm", "wms", "wordpress", "work", "worker", "works",
    "workshop", "world", "wp", "ws", "wss", "wt", "wu",
    "ww1", "ww2", "ww3", "www4", "www5", "x", "x1",
    "xa", "xb", "xd", "xe", "xf", "xg", "xi", "xm",
    "xn", "xo", "xp", "xr", "xs", "xt", "xu", "y",
    "ya", "yb", "z", "za", "zero", "zh", "zimbra",
    "zip", "zm", "zone", "zoo", "zp", "zw",
]

DEEP_GENERATED = (
    [f"{p}{s}" for p in ["dev", "staging", "test", "prod", "api", "app",
     "web", "db", "mail", "ns", "server", "cloud", "k8s", "docker",
     "node", "worker", "backend", "frontend", "cache", "queue", "cdn"]
     for s in ["1", "2", "3", "4", "5", "01", "02", "03", "04", "05",
               "-01", "-02", "-03", "-1", "-2", "-3", "-dev", "-staging",
               "-prod", "-test", "-qa", "-uat"]]
    +
    [f"{p}-{s}" for p in ["us", "eu", "ap", "east", "west", "north",
     "south", "asia", "uk", "de", "fr", "jp", "au", "in", "br", "ca"]
     for s in ["1", "2", "3", "prod", "staging", "dev", "test"]]
    +
    [f"{p}-{s}" for p in ["internal", "ext", "pub", "priv", "corp", "vpn"]
     for s in ["api", "web", "app", "gw", "proxy", "mail", "dns"]]
)


def get_wordlist(scan_type: str) -> List[str]:
    """Return subdomain wordlist based on scan type."""
    if scan_type == "quick":
        return list(set(BASE_WORDS))  # ~160
    elif scan_type == "standard":
        return list(set(BASE_WORDS + EXTENDED_WORDS))  # ~800
    elif scan_type == "deep":
        return list(set(BASE_WORDS + EXTENDED_WORDS + DEEP_GENERATED))  # ~1500+
    return list(set(BASE_WORDS))


# ─── DNS RESOLUTION ─────────────────────────────────────────────────────────

async def resolve_subdomain(subdomain: str, domain: str) -> Optional[dict]:
    """Try to resolve a subdomain via DNS."""
    fqdn = f"{subdomain}.{domain}"
    try:
        loop = asyncio.get_event_loop()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = await loop.run_in_executor(None, lambda: resolver.resolve(fqdn, 'A'))
        ip = str(answers[0]) if answers else None
        if ip:
            return {"subdomain": fqdn, "ip": ip, "source": "bruteforce"}
    except:
        pass
    return None


# ─── OSINT SOURCES ───────────────────────────────────────────────────────────

async def query_crtsh(domain: str) -> Set[str]:
    """Query crt.sh Certificate Transparency logs."""
    found: Set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                follow_redirects=True
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for n in entry.get("name_value", "").split("\n"):
                        n = n.strip().lower()
                        if n and n.endswith(f".{domain}") and "*" not in n:
                            found.add(n)
    except:
        pass
    return found


async def query_hackertarget(domain: str) -> Set[str]:
    """Query HackerTarget free API for subdomains."""
    found: Set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}"
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split("\n"):
                    parts = line.split(",")
                    if parts and parts[0].strip().endswith(f".{domain}"):
                        found.add(parts[0].strip().lower())
    except:
        pass
    return found


async def query_alienvault(domain: str) -> Set[str]:
    """Query AlienVault OTX for subdomains."""
    found: Set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers={"Accept": "application/json"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").lower()
                    if hostname and hostname.endswith(f".{domain}"):
                        found.add(hostname)
    except:
        pass
    return found


async def query_rapiddns(domain: str) -> Set[str]:
    """Query RapidDNS for subdomains."""
    found: Set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                import re
                pattern = re.compile(r'([\w\-\.]+\.' + re.escape(domain) + r')')
                matches = pattern.findall(resp.text)
                for m in matches:
                    m = m.lower().strip(".")
                    if m.endswith(f".{domain}") and "*" not in m:
                        found.add(m)
    except:
        pass
    return found


# ─── HTTP PROBING ────────────────────────────────────────────────────────────

async def check_http(subdomain: str) -> dict:
    """Check HTTP status and server header for a subdomain."""
    result = {"status_code": None, "server": None}
    for scheme in ["https", "http"]:
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                resp = await client.head(f"{scheme}://{subdomain}", follow_redirects=True)
                result["status_code"] = resp.status_code
                result["server"] = resp.headers.get("server", None)
                return result
        except:
            continue
    return result


# ─── MAIN SCAN FUNCTION ─────────────────────────────────────────────────────

async def run_subdomain_scan(
    domain: str,
    scan_type: str = "quick",
    use_crtsh: bool = True,
    concurrency: int = 150,
    progress_callback=None,
    cancel_event: Optional[asyncio.Event] = None
) -> dict:
    """
    Multi-source subdomain enumeration:
      Phase 1: DNS brute-force with large wordlist
      Phase 2: OSINT — crt.sh, HackerTarget, AlienVault, RapidDNS
      Phase 3: DNS resolve OSINT results
      Phase 4: HTTP probe all found subdomains
    """
    start_time = datetime.now(timezone.utc)
    wordlist = get_wordlist(scan_type)
    all_subdomains: Dict[str, dict] = {}

    # ── Phase 1: DNS Bruteforce ──
    semaphore = asyncio.Semaphore(concurrency)

    async def limited_resolve(sub):
        if cancel_event and cancel_event.is_set():
            return None
        async with semaphore:
            if cancel_event and cancel_event.is_set():
                return None
            res = await resolve_subdomain(sub, domain)
            if res and progress_callback:
                await progress_callback({
                    "type": "subdomain_found",
                    "data": res
                })
            return res

    tasks = [limited_resolve(sub) for sub in wordlist]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            all_subdomains[r["subdomain"]] = r

    # ── Phase 2: OSINT Sources (parallel) ──
    osint_names: Set[str] = set()

    if use_crtsh:
        osint_tasks = [
            query_crtsh(domain),
            query_hackertarget(domain),
            query_alienvault(domain),
            query_rapiddns(domain),
        ]
        osint_results = await asyncio.gather(*osint_tasks, return_exceptions=True)

        for result in osint_results:
            if isinstance(result, set):
                osint_names.update(result)

    # ── Phase 3: Resolve OSINT subdomains ──
    new_osint_names = osint_names - set(all_subdomains.keys())
    if new_osint_names:
        resolve_sem = asyncio.Semaphore(100)

        async def resolve_osint(name):
            if cancel_event and cancel_event.is_set():
                return None
            async with resolve_sem:
                if cancel_event and cancel_event.is_set():
                    return None
                try:
                    loop = asyncio.get_event_loop()
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    answers = await loop.run_in_executor(
                        None, lambda n=name: resolver.resolve(n, 'A')
                    )
                    ip = str(answers[0]) if answers else None
                    res = {"subdomain": name, "ip": ip, "source": "osint"}
                    if res and progress_callback:
                        await progress_callback({
                            "type": "subdomain_found",
                            "data": res
                        })
                    return res
                except:
                    res = {"subdomain": name, "ip": None, "source": "osint"}
                    if progress_callback:
                        await progress_callback({
                            "type": "subdomain_found",
                            "data": res
                        })
                    return res

        osint_resolve_tasks = [resolve_osint(n) for n in new_osint_names]
        osint_resolved = await asyncio.gather(*osint_resolve_tasks)

        for r in osint_resolved:
            if r and r["subdomain"] not in all_subdomains:
                all_subdomains[r["subdomain"]] = r

    # ── Phase 4: HTTP Probe all found ──
    http_semaphore = asyncio.Semaphore(40)

    async def check_with_limit(info):
        if cancel_event and cancel_event.is_set():
            return
        async with http_semaphore:
            if cancel_event and cancel_event.is_set():
                return
            http_info = await check_http(info["subdomain"])
            info["status_code"] = http_info["status_code"]
            info["server"] = http_info["server"]
            if progress_callback:
                await progress_callback({
                    "type": "subdomain_updated",
                    "data": info
                })

    if all_subdomains:
        http_tasks = [check_with_limit(info) for info in all_subdomains.values()]
        await asyncio.gather(*http_tasks)

    # Build final results
    subdomain_list = sorted(all_subdomains.values(), key=lambda x: x["subdomain"])

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    return {
        "subdomains": subdomain_list,
        "total_found": len(subdomain_list),
        "scan_duration": round(duration, 2),
    }
