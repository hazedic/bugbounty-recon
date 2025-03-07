#!/usr/bin/env python3
import subprocess
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import argparse
import logging
import json
from urllib.parse import urlparse
import shutil
import time
from colorama import init, Fore, Style
import requests
import urllib3

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ColoredFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Fore.YELLOW + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.GREEN + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.MAGENTA + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logging.basicConfig(
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stdout)],
    force=True
)
logging.getLogger().handlers[0].setFormatter(ColoredFormatter())

parser = argparse.ArgumentParser(description="Automated reconnaissance tool to enumerate target domain assets")
parser.add_argument("domain", help="Target domain (e.g., example.com)")
parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed command logs")
parser.add_argument("-s", "--screenshot", action="store_true", help="Take screenshots of all subdomains found for the target domain")
args = parser.parse_args()

if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

def log_info(message):
    logging.info(message)

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "subfinder_threads": 100,
    "httpx_threads": 50,
    "httpx_timeout": 5,
    "katana_depth": 5,
    "katana_concurrency": 20,
    "exclude_extensions": "ttf,woff,woff2,svg,png,jpg,jpeg,gif,mp4,mp3,pdf,css,js,ico,eot",
    "dns_resolvers": "8.8.8.8,1.1.1.1",
    "gowitness_timeout": 20,
    "required_tools": [
        "subfinder",
        "assetfinder",
        "amass",
        "httpx",
        "waymore",
        "katana",
        "gospider",
        "gowitness"
    ]
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            logging.debug(f"Loaded configuration from {CONFIG_FILE}: {config}")
            return config
    logging.debug(f"Using default configuration: {DEFAULT_CONFIG}")
    return DEFAULT_CONFIG

CONFIG = load_config()

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def check_required_tools():
    missing_tools = [tool for tool in CONFIG['required_tools'] if not check_tool_installed(tool)]
    if missing_tools:
        logging.error(f"The following required tools are missing: {', '.join(missing_tools)}")
        logging.error("Please install them and try again.")
        exit(1)

def count_lines(file_path):
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return sum(1 for line in f if line.strip())
    return 0

def is_contentless_redirect(url):
    try:
        response = requests.head(url, allow_redirects=False, timeout=5, verify=False)
        return response.status_code in (301, 302, 303, 307, 308)
    except requests.RequestException as e:
        logging.warning(f"Failed to check {url} for content: {str(e)}")
        return True

def check_urls_content(urls):
    with ThreadPoolExecutor(max_workers=min(20, len(urls))) as executor:
        results = list(executor.map(is_contentless_redirect, urls))
    return all(results)

def run_command(command, output_file=None, task_description="Processing", input_file=None):
    if input_file and not os.path.exists(input_file):
        logging.error(f"Input file missing for {task_description}: {input_file} does not exist")
        return None
    if input_file and count_lines(input_file) == 0:
        logging.warning(f"Input file is empty for {task_description}: {input_file}")
        logging.debug(f"  - Contents of empty input file {input_file}: (empty)")
    try:
        tools = [cmd.split()[0] for cmd in command.split('|')]
        valid_tools = [tool for tool in tools if tool in CONFIG['required_tools']]
        if not all(check_tool_installed(tool) for tool in valid_tools):
            missing_tools = [tool for tool in valid_tools if not check_tool_installed(tool)]
            logging.error(f"Required tools not found for {task_description}: {', '.join(missing_tools)}")
            return None
        start_time = time.time()
        logging.debug(f"  - Command: {command}")
        if output_file:
            logging.debug(f"  - Output file: {output_file}")
        if input_file:
            with open(input_file, 'r') as f:
                content = f.read().strip()
                if len(content.splitlines()) > 3:
                    sample_lines = '\n      '.join(content.splitlines()[:3])
                    logging.debug(f"  - Input data (first 3 lines): \n      {sample_lines} [... truncated]")
                else:
                    logging.debug(f"  - Input data: {content}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, errors='replace')
        if output_file and os.path.exists(output_file) and count_lines(output_file) > 0:
            lines = count_lines(output_file)
            logging.debug(f"  - Result: {lines} lines written to {output_file}")
            with open(output_file, 'r') as f:
                sample = '\n      '.join(f.read().splitlines()[:3])
                logging.debug(f"  - Sample output (first 3 lines): \n      {sample}")
            log_info(f"✓ {task_description} completed - {lines} items processed in {time.time() - start_time:.2f}s")
            return output_file
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error occurred"
            logging.error(f"Task failed: {task_description}\nError: {error_msg}")
            logging.debug(f"  - Command stdout: {result.stdout}")
            logging.debug(f"  - Command stderr: {result.stderr}")
            return None
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            lines = count_lines(output_file)
            logging.debug(f"  - Result: {lines} lines written to {output_file}")
            if lines > 0:
                with open(output_file, 'r') as f:
                    sample = '\n      '.join(f.read().splitlines()[:3])
                    logging.debug(f"  - Sample output (first 3 lines): \n      {sample}")
            log_info(f"✓ {task_description} completed - {lines} items processed in {time.time() - start_time:.2f}s")
            return output_file
        lines = len(result.stdout.splitlines())
        if lines > 0:
            logging.debug(f"  - Result: {lines} lines returned")
            sample_output = '\n      '.join(result.stdout.splitlines()[:3])
            logging.debug(f"  - Sample output (first 3 lines): \n      {sample_output}")
        log_info(f"✓ {task_description} completed - {lines} items processed in {time.time() - start_time:.2f}s")
        return result.stdout
    except Exception as e:
        logging.error(f"Exception in {task_description}: {str(e)}")
        return None

def run_parallel(commands, phase_name="Parallel tasks"):
    results = []
    total_tasks = len(commands)
    successful_tasks = 0
    max_workers = min(os.cpu_count() * 2, total_tasks) or 4
    log_info(f"Starting {phase_name} ({total_tasks} tasks)")
    log_info("─" * 50)
    logging.debug(f"[Phase: {phase_name}]")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_command, cmd['command'], cmd.get('output'), cmd.get('task'), cmd.get('input')): cmd for cmd in commands}
        for future in futures:
            try:
                result = future.result()
                if result:
                    successful_tasks += 1
                    results.append(result)
            except Exception as e:
                logging.warning(f"Task {futures[future]['task']} failed with exception: {str(e)}. Continuing with other results.")
            progress = successful_tasks / total_tasks
            bar_length = 20
            filled = int(bar_length * progress)
            bar = "█" * filled + "─" * (bar_length - filled)
            logging.info(f"Progress: [{bar}] {successful_tasks}/{total_tasks} tasks ({progress * 100:.1f}%)")

    log_info("─" * 50)
    log_info(f"{phase_name} completed with {successful_tasks}/{total_tasks} successful tasks")
    return results

def normalize_url(url):
    try:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
    except Exception:
        return None

def merge_and_deduplicate(files, output_file):
    if not files:
        logging.warning("No files to merge. Creating empty output file.")
        with open(output_file, 'w') as f:
            f.write('')
        return output_file
    if not all(os.path.exists(f) for f in files):
        logging.error(f"Cannot merge files: One or more input files missing: {', '.join([f for f in files if not os.path.exists(f)])}")
        return None
    unique_urls = set()
    for file in files:
        with open(file, 'r') as f:
            for line in f:
                normalized = normalize_url(line)
                if normalized:
                    unique_urls.add(normalized)

    with open(output_file, 'w') as f:
        f.write('\n'.join(sorted(unique_urls)))
    lines = len(unique_urls)
    log_info(f"✓ URL merging and deduplication completed - {lines} unique URLs saved to {output_file}")
    logging.debug(f"  - Result: {lines} unique URLs saved")
    with open(output_file, 'r') as f:
        sample = '\n      '.join(f.read().splitlines()[:3])
        logging.debug(f"  - Sample URLs (first 3): \n      {sample}")
    return output_file

def automate_scan(domain):
    output_dir = f"scan_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    subfinder_domains = f"{output_dir}/subfinder_domains.txt"
    assetfinder_domains = f"{output_dir}/assetfinder_domains.txt"
    amass_domains = f"{output_dir}/amass_domains.txt"
    merged_domains = f"{output_dir}/merged_domains.txt"
    httpx_alive_domains = f"{output_dir}/httpx_alive_domains.txt"
    waymore_urls = f"{output_dir}/waymore_urls.txt"
    katana_urls = f"{output_dir}/katana_urls.txt"
    gospider_urls = f"{output_dir}/gospider_urls.txt"
    merged_urls = f"{output_dir}/merged_urls.txt"
    gowitness_db = f"{output_dir}/gowitness.sqlite3"

    log_info(f"Starting reconnaissance for {domain}")
    log_info("═" * 50)
    initial_commands = [
        {"command": f"subfinder -d {domain} -t {CONFIG['subfinder_threads']} -silent -nW", 
         "output": subfinder_domains, 
         "task": "Subdomain enumeration with subfinder"},
        {"command": f"assetfinder -subs-only {domain}", 
         "output": assetfinder_domains, 
         "task": "Subdomain enumeration with assetfinder"},
        {"command": f"timeout 600s amass enum -active -d {domain} -r {CONFIG['dns_resolvers']} -v | awk '{{print $1}}' | grep -v '^[0-9]' > {amass_domains}", 
         "output": amass_domains, 
         "task": "Subdomain enumeration with amass"}
    ]
    subdomain_results = run_parallel(initial_commands, phase_name="Subdomain enumeration")
    if not subdomain_results:
        logging.error("No subdomains enumerated successfully. Aborting reconnaissance.")
        return

    log_info("─" * 50)
    merge_result = run_command(
        rf"cat {subfinder_domains} {assetfinder_domains} {amass_domains} | awk '{{print $1}}' | grep -E '^[a-zA-Z0-9.-]+\.{domain}$' | sort -u -f | grep -v '^\*'",
        merged_domains,
        "Merging subdomain results"
    )
    if not merge_result:
        logging.error("Failed to merge subdomains. Aborting reconnaissance.")
        return

    alive_result = run_command(
        rf"httpx -list {merged_domains} -threads {CONFIG['httpx_threads']} -timeout {CONFIG['httpx_timeout']} -silent -mc 200,301,302,304,307,308,403,401,503,500 -follow-redirects -cl | awk '{{print $1}}'",
        httpx_alive_domains,
        "Checking alive domains with httpx",
        input_file=merged_domains
    )
    if not alive_result or count_lines(httpx_alive_domains) == 0:
        logging.warning("No alive domains found with httpx. Using merged domains as fallback.")
        shutil.copy(merged_domains, httpx_alive_domains)
        alive_result = httpx_alive_domains

    if count_lines(httpx_alive_domains) == 0:
        logging.error("No valid domains available for URL crawling. Aborting reconnaissance.")
        return

    log_info("─" * 50)
    exclude_filter = CONFIG['exclude_extensions'].replace(',', '|')
    gospider_output_dir = f"{output_dir}/gospider_output"
    os.makedirs(gospider_output_dir, exist_ok=True)
    
    scan_commands = [
        {"command": rf"waymore -i {domain} -mode U -oU {waymore_urls}", 
         "output": waymore_urls, 
         "task": "URL crawling with waymore"},
        {"command": f"katana -list {httpx_alive_domains} -d {CONFIG['katana_depth']} -c {CONFIG['katana_concurrency']} -js-crawl -ef {CONFIG['exclude_extensions']} -fs rdn", 
         "output": katana_urls, 
         "task": "URL crawling with katana", 
         "input": httpx_alive_domains},
        {"command": rf"gospider -S {httpx_alive_domains} -d 5 -c 30 -t 20 -o {gospider_output_dir} --whitelist-domain {domain} --blacklist 'png|jpg|jpeg|gif|mp4|pdf' --js --sitemap --robots -a -w -r --subs -m 15 > {gospider_urls}", 
         "output": gospider_urls, 
         "task": "URL crawling with gospider", 
         "input": httpx_alive_domains}
    ]
    url_results = []
    
    waymore_cmd = scan_commands[0]
    result = run_command(waymore_cmd['command'], waymore_cmd['output'], waymore_cmd['task'])
    if result:
        url_results.append(result)
    else:
        logging.warning(f"{waymore_cmd['task']} failed, but continuing with other tools.")

    for cmd in scan_commands[1:]:
        with open(cmd['input'], 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        if check_urls_content(urls):
            logging.warning(f"Skipping {cmd['task']} as all input URLs ({', '.join(urls)}) are contentless redirects.")
            continue
        result = run_command(cmd['command'], cmd['output'], cmd['task'], cmd['input'])
        if result:
            url_results.append(result)
        else:
            logging.warning(f"{cmd['task']} failed, but continuing with other tools.")

    if not url_results:
        logging.warning("No URLs crawled successfully. Proceeding with empty results.")

    log_info("─" * 50)
    merge_urls_result = merge_and_deduplicate(url_results, merged_urls)
    if not merge_urls_result:
        logging.warning("No URLs collected. Reconnaissance completed with empty results.")
        return

    if args.screenshot:
        log_info("─" * 50)
        log_info("Starting screenshot capture with gowitness")
        gowitness_cmd = f"gowitness scan file -f {merged_domains} --save-content --write-db --write-db-uri sqlite://{gowitness_db} --screenshot-path {output_dir}/screenshots --timeout {CONFIG['gowitness_timeout']}"
        run_command(
            gowitness_cmd,
            task_description="Capturing screenshots with gowitness",
            input_file=merged_domains
        )
        if os.path.exists(gowitness_db):
            log_info(f"✓ Screenshots captured and saved to {gowitness_db}")
        else:
            logging.warning("Gowitness failed to generate screenshots or database.")

    logging.info("═" * 50)
    logging.info(f"Reconnaissance completed! Final results saved in {merged_urls}")
    logging.info("Summary:")
    logging.info(f"  - Subdomains found: {count_lines(merged_domains)}")
    logging.info(f"  - Alive domains: {count_lines(httpx_alive_domains)}")
    logging.info(f"  - Total URLs crawled: {count_lines(merged_urls)}")
    if args.screenshot and os.path.exists(gowitness_db):
        logging.info(f"  - Screenshots saved: {gowitness_db}")
    logging.info("═" * 50)

if __name__ == "__main__":
    check_required_tools()
    automate_scan(args.domain)
