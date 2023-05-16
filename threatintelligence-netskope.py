import re, requests, json, csv, html2text, argparse, logging
from io import StringIO
from bs4 import BeautifulSoup

# Read the configuration file
with open('config.json') as file:
    config = json.load(file)

token_v1 = config['tokens']['token_v1']
token_v2 = config['tokens']['token_v2']
tenant = config['tenant']
filelist_sha256 = config['filelist_sha256']
filelist_md5 = config['filelist_md5']
debug_enabled = config.get('debug', {}).get('enabled', False)
debug_level = config.get('debug', {}).get('level', False)

# Map the debug level to the corresponding logging level
if debug_level == 'debug':
    logging_level = logging.DEBUG
elif debug_level == 'info':
    logging_level = logging.INFO
elif debug_level == 'warning':
    logging_level = logging.WARNING
elif debug_level == 'error':
    logging_level = logging.ERROR
elif debug_level == 'critical':
    logging_level = logging.CRITICAL
else:
    logging_level = logging.INFO

if debug_enabled:
    print(f"Debug is enabled with level: {debug_level}")
    # Set up the logging configuration
    logging.basicConfig(level=logging_level)
    # Perform additional debug-related actions based on the level
    # For example, enable logging at the specified level
else:
    print("Debug is disabled")



feeds = {
    'all': '',
    'rescure_ip': 'https://rescure.me/rescure_blacklist.txt',
    'cins_ip': 'http://cinsscore.com/list/ci-badguys.txt',
    'feodo_recommended_ip': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    'feodo_ip': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    'urlhaus_url': 'https://urlhaus.abuse.ch/downloads/text/',
    'emergingthreats_tor_snort': 'https://rules.emergingthreats.net/blockrules/emerging-tor.rules',
#    'rescure_hash': 'https://rescure.me/rescure_malware_hashes.txt', (Removed because Netskope does not support SHA1 hashes)
    'rescure_domain': 'https://rescure.me/rescure_domain_blacklist.txt',
    'securityscorecard_ip': 'https://raw.githubusercontent.com/securityscorecard/SSC-Threat-Intel-IoCs/master/KillNet-DDoS-Blocklist/ipblocklist.txt',
    'rutgers_ip': 'https://report.cs.rutgers.edu/DROP/attackers',
    'emergingthreats_ip': 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
    'banlist_ip': 'https://www.binarydefense.com/banlist.txt',
    'digitalside_ip': 'https://osint.digitalside.it/Threat-Intel/lists/latestips.txt',
    'digitalside_url': 'https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt',
    'digitalside_domain': 'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt',
    'abusetracker_ip': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    'ipsum_ip': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
    'jamesbrine_ip': 'https://jamesbrine.com.au/iplist.txt',
    'malshare_hash': 'https://www.malshare.com/daily/malshare.current.sha256.txt',
    'malware_bazaar_hash': 'https://bazaar.abuse.ch/export/txt/sha256/recent/',
    'openphish_url': 'https://openphish.com/feed.txt',
    'phishtank_csv': 'http://data.phishtank.com/data/online-valid.csv',
    'abusetracker_ip': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    'threatminer_url': 'https://www.threatminer.org/getData.php?e=malware_container&q=malware_delivery&t=21&rt=3&p=1',
    'firehol_ip': 'https://iplists.firehol.org/files/firehol_level1.netset',
    'blocklist_ip': 'http://lists.blocklist.de/lists/dnsbl/all.list',
}

parser = argparse.ArgumentParser(description="Process feeds.")
parser.add_argument("-f", "--feed", help="Specify the feed name", choices=feeds.keys(), required=True)
args = parser.parse_args()
feed_to_import = args.feed

# Global variables
content = ''
filtered_urls = []

ua_headers={"User-Agent": "Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"}

def is_md5_hash(hash_string):
    return re.match(r'^[a-fA-F0-9]{32}$', hash_string) is not None

def is_sha256_hash(hash_string):
    return re.match(r'^[a-fA-F0-9]{64}$', hash_string) is not None

def process_html(content):
    soup = BeautifulSoup(content, 'html.parser')
    texts = []
    for link in soup.find_all('a', href=lambda href: href.startswith('uri.php')):
        text = link.get_text()
        text = text.encode("utf8")
        text = text.replace(b"\\r",b"\r")
        text = str(text)[2:-1]
        question_mark_count = text.count("?")
        if "{" in text:
            None
        elif "[" in text:
            None
        elif "∾" in text:
            None
        elif '"' in text:
            None
        elif '\\' in text:
            None
        elif question_mark_count != 1:
            None
        elif question_mark_count != 1 and question_mark_count != 0:
            None
        elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,}', text.strip()):
            None
        else:
            texts.append(text)
        logging.debug(f'Extracted URLs: {texts}')
    return texts

def download_content(url, feed):
    logging.debug(f'Trying to get data from: {url} for feed {feed}')
    try:
        response = requests.get(url, headers=ua_headers)
        logging.debug(f'Response: {response.text}')
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to download content from {url}: {str(e)}")
        return None
    if feed == 'threatminer_url':
        contentlist = process_html(response.text)
        return contentlist
    elif feed == 'emergingthreats_tor_snort':
        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        ip_addresses = re.findall(ip_pattern, response.text)
        return ip_addresses
    else:
        return response.text

def csv_process(content):
    data = []
    csv_file = StringIO(content)
    reader = csv.DictReader(csv_file)
    for row in reader:
        url = row['url']
        data.append(url)
    return data

def extract_urllist(content, feed):
    urllist = []
    try:
        lines = content.split('\n')
    except:
        lines = content
    for line in lines:
        url_match = re.match(r'^(https?://\S+)', line.strip())
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$', line.strip()):
            subnet = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})$', line.strip())
            subnet = subnet.group(1)
            if re.match(r'(0\.0\.0\.0\/.*)', subnet):
                None
            else:
                urllist.append(subnet)
        elif re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line.strip()):
            ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line.strip())
            ip = ip.group(1)
            urllist.append(ip)
        elif re.match(r'^(https?://\S+)', line.strip()):
            url = re.match(r'^(https?://\S+)', line.strip())
            url = url.group(1)
            url = url.encode("utf8")
            url = url.replace(b"\\r",b"\r")
            url = str(url)[2:-1]
            question_mark_count = url.count("?")
            if '{' in url:
                None
            elif "[" in url:
                None
            elif "∾" in url:
                None
            elif '\\' in text:
                None
            elif '"' in url:
                None
            elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,}$', url.strip()):
                None
            else:
                urllist.append(url)
        elif re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', line.strip()):
            domain = re.match(r'^(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})$', line.strip())
            domain = domain.group(1)
            urllist.append(domain)
    return urllist

def patch_urllist(urllist, feed):
    url = f'https://{tenant}.goskope.com/api/v2/policy/urllist'
    headers = {
        'accept': 'application/json',
        'Netskope-Api-Token': f'{token_v2}',
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)
    name_id_dict = {item['name']: item['id'] for item in response.json()}
    id_value = name_id_dict.get(feed)
    url = f'https://{tenant}.goskope.com/api/v2/policy/urllist/' + str(id_value)
    response = requests.get(url, headers=headers)
    response = response.json()
    existingurls = response["data"]["urls"]
    logging.debug(f'Existing ULRs: {existingurls}')
    unique_values = set(urllist).symmetric_difference(set(existingurls))
    logging.debug(f'Unique Values: {unique_values}')
    unique_list = list(unique_values)
    if unique_list == []:
        logging.info(f'Data is already up to date')
        None
    else:
        payload = {
            'name': f'{feed}',
            'data': {
                'urls': unique_list,
                'type': 'exact'
                }
                }
        url = url + '/append'
        logging.debug(f'URL: {url}')
        logging.debug(f'Headers: {headers}')
        logging.debug(f'Headers: {payload}')
        response = requests.patch(url, headers=headers, json=payload)
        response.raise_for_status()
        return response, unique_values

def add_urllist_to_api(urllist, feed):
    url = f'https://{tenant}.goskope.com/api/v2/policy/urllist'
    headers = {
        'accept': 'application/json',
        'Netskope-Api-Token': f'{token_v2}',
        'Content-Type': 'application/json'
    }
    # urllist = ['https://neerdael.nl']
    payload = {
        'name': f'{feed}',
        'data': {
            'urls': urllist,
            'type': 'exact'
        }
    }
    logging.debug(f'URL: {url}')
    logging.debug(f'Headers: {headers}')
    logging.debug(f'Payload: {payload}')
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.debug(f'Failed adding URLs')
        error_message = str(e)
        if response is not None:
            try:
                error_json = response.json()
                error_message = error_json.get("message", error_message)
                if error_message == 'Creating a list using duplicated name is not allowed':
                    logging.debug(f"Trying to patch existing list")
                    response, unique_lines = patch_urllist(urllist, feed)
                    print(f'Imported {len(unique_lines)} from {feed} to Netskope')
                else:
                    logging.debug(f"Failed to add data to API: {error_message}")
            except json.JSONDecodeError:
                logging.debug(f"Failed to add data to API: {error_message}")
                return None


def extract_hashes(content):
    hashes = []
    lines = content.split('\n')
    for line in lines:
        if re.match(r'^[a-fA-F0-9]{64}$', line.strip()):
            hashes.append(line.strip())
    return hashes

def add_hashes_to_api(hashes, feed):
    url = f'https://{tenant}.goskope.com/api/v1/updateFileHashList?token={token_v1}'
    payload = {"name" : f"{filelist}","list" : f"{','.join(hashes)}"}
    logging.debug(f'Payload: {payload}')
    try:
        response = requests.patch(url, json=payload)
        logging.debug(f'Response: {response.json()}')
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        error_message = str(e)
        if response is not None:
            try:
                error_json = response.json()
                error_message = error_json.get("message", error_message)
            except json.JSONDecodeError:
                pass
        logging.debug(f"Failed to add data to API: {error_message}")
        return None


def check_type(feed):
    logging.debug(f'Type parameter {feed}')
    if 'csv' in feed:
        type = 'csv'
        return type
    elif 'hash' in feed:
        type = 'hash'
        return type
    else:
        type = 'urllist'
        return type


def csv_final(feed_content, feed, type):
    logging.debug('Matched Web Profile')
    logging.debug(f'Processing {type} feed')
    logging.debug(f'Pre-Processing Data: {feed_content}')
    content = csv_process(feed_content)
    logging.debug(f'Post-Processing Data: {content}')
    try:
        response = add_urllist_to_api(content)
        logging.info(f'Imported {len(content)} from {feed} to Netskope')
    except:
        None

def urllist_final(feed_content, feed, type):
    logging.debug('Matched Web Profile')
    try:
        if 'type' == 'url' :
            logging.debug(f'Processing {feed} feed')
            urllist = add_urllist_to_api(feed_content, feed)
        elif type == 'snort':
            logging.debug(f'Processing {feed} feed')
            urllist = add_urllist_to_api(feed_content, feed)
        else:
            logging.debug(f'Processing {type} feed')
            urllist = extract_urllist(feed_content, feed)
            # Add IP subnets to the API
            response = add_urllist_to_api(urllist, feed)
        print(f'Imported {len(urllist)} from {feed} to Netskope')
    except:
        None

def hash_final(feed_content, feed, type):
    logging.debug('Matched File Profile')
    logging.debug(f'Processing {type} feed')
    hashes = extract_hashes(feed_content)
    # Add IP subnets to the API
    try:
        response = add_hashes_to_api(hashes, feed)
        print(f'Imported {len(hashes)} from {feed} to Netskope')
    except:
        None

def process_type(type, feed_content, feed):
    if type == 'urllist':
        logging.debug(f'Starting the process for {type} imports for {feed}')
        logging.debug(f'data: {feed_content}')
        urllist_final(feed_content, feed, type)
    elif type == 'hash':
        logging.debug(f'Starting the process for {type} imports for {feed}')
        logging.debug(f'data: {feed_content}')
        hash_final(feed_content, feed, type)
    elif type == 'csv':
        logging.debug(f'Starting the process for {type} imports for {feed}')
        logging.debug(f'data: {feed_content}')
        csv_final(feed_content, feed, type)

# Retrieve the desired feed content
if feed_to_import == 'all':
    logging.debug('Processing all importable feeds')
    for feed in feeds.keys():
        feed_url = feeds[feed]
        feed_content = download_content(feed_url, feed_to_import)
        logging.debug(f'Trying to find file type for {feed}')
        type = check_type(feed_to_import)
        logging.debug(f'Type: {type}')
        process_type(type, feed_content, feed_to_import)
elif feed_to_import in feeds.keys():
    logging.debug(f'Processing {feed_to_import}')
    feed_url = feeds[feed_to_import]
    feed_content = download_content(feed_url, feed_to_import)
    logging.debug(f'Trying to find file type for {feed_to_import}')
    type = check_type(feed_to_import)
    logging.debug(f'Type: {type} from {feed_to_import}')
    process_type(type, feed_content, feed_to_import)
else:
    logging.debug("Invalid feed name")
