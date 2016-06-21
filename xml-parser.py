#!/usr/bin/env python
# ~*~ coding: utf-8 ~*~

""" Parse xml dump of blacklist and generate different usefull
files for next blocking by DNS, DPI etc.

Output of xml parsing:
- Generate files of raw items
- Generate RPZ zone file
- Generate Mikrotik script file

"""
import logging
import xml.etree.ElementTree as ET
from os import path
from shutil import copy
from subprocess import call
from sys import argv
from time import time
from urllib import quote
from urlparse import urlparse

WORK_DIR = path.dirname(path.realpath(__file__))
# Location of reestr dump
DUMP_DIR = "%s/dump/" % WORK_DIR
LOG_DIR = "%s/log/" % WORK_DIR

try:
    logging.basicConfig(format='%(asctime)s - %(levelname)s:%(message)s',
        filename='%sxml-parser.log' % LOG_DIR,level=logging.DEBUG)
except IOError as Err:
    exit(Err)

logging.info('--- Parsing started ---')

# Location master dir of your bind
DNS_DIR = ""
# RPZ zone from named.conf
ZONE_FILE = 'db.rpz.zone'
# RPZ zone file for bind
ZONE_NAME = 'rpz.zone.'
# Target of DNS resolve
REDIR_DOMAIN = 'block.example.org.'

# Location of www dir for fetching by HTTP or HTTPS 
WWW_DIR = ""

# Mikrotik script for import address list
MTIK_FILE = 'import_blacklist.rsc'
# Mikrotik ip firewall address list
MTIK_LIST = 'reestr_rkn'



def normalize_url(url):
    """ Build normal URL for SCE blocking

    """

    url = url.lower()
    o = urlparse(url)
    scheme = o.scheme
    header = "%s://" % scheme
    url = url.split(header, 1)[1]
    url = quote(url.encode('utf8'))
    url = '%s%s' % (header, url)

    return scheme, url

def write_parsed_data(file_name, data, path=DUMP_DIR):
    """ Write parsed data to spec file

    """

    with open(DUMP_DIR + file_name, 'w') as f:
        data = sorted(set(data))
        for item in data:
            f.write("%s\n" % item)



def generate_zone_file(domains):
    """ Generate RPZ zone file for bind with explicitly blocked
    domains, and domains that relate to Https

    """

    header = (";RPZ\n$TTL\t10\n@\tIN SOA %s %s (\n" 
              "\t%s;\n\t3600;\n\t300;\n\t86400;\n"
              "\t60 )\n@\tIN\tNS\tlocalhost.\n\n" 
        % (ZONE_NAME, ZONE_NAME, int(time())))
    with open("%s/%s" % (DUMP_DIR, ZONE_FILE), 'w') as f:
        f.write(header)
        for domain in domains:
            f.write("%s\t\t\t\tCNAME\t%s\n" % (domain, REDIR_DOMAIN))

def generate_mikrotik_script(ip_hosts):
    """ Generates an import file for Mikrotik with a list of explicitly
    blocked IP addresses and addresses belonging to HTTPS

    """

    with open("%s/%s" % (DUMP_DIR, MTIK_FILE), 'w') as f:
        for host in ip_hosts:
            f.write("/ip firewall address-list add list=reestr_rkn address=%s\n" % 
                host)


# Parsed data
http_urls = []
http_ips = []
http_domains = []
https_urls = []
https_ips = []
https_domains = []
domains = []
blocked_ips = []
blocked_domains = []

# Init XML tree from raw dump file
logging.info('Load xml dump')
try:
    tree = ET.parse('%sdump.xml' % DUMP_DIR)
except IOError as Err:
    logging.error(Err)
    exit(Err)

root = tree.getroot()

updateTime = root.get('updateTIme')
updateTimeUrgently = root.get('updateTimeUrgently')
formatVersion= root.get('formatVersion')

logging.info("Dump update time %s" % updateTime)
logging.info("Dump update time urgently %s" % updateTimeUrgently)

for record in root :
    is_https = False
    is_ByDomain = False
    is_ByIP = False

    contentId = record.get('id')
    includeTime = record.get('includeTime')
    urgencyType = record.get('urgencyType')
    entryType = record.get('entryType')
    contentHash = record.get('hash')

    """ Block types:
    default - block by standart rules
    domain  - block by domain name
    ip      - block by IP address
    """
    blockType = record.get('blockType')
    if (blockType == 'domain'):
        is_ByDomain = True
    elif (blockType == 'ip'):
        id_ByIP = True

    decision = record.find('decision')
    if decision is not None:
        decisionDate = decision.get('date')
        decisionOrg = decision.get('org')
        decisionNumber = decision.get('number')

    # HTTP and HTTPS to another lists
    urls = record.findall('url')
    if urls is not None:
        for url in urls:
            url = url.text
            scheme, url = normalize_url(url)
            if scheme == 'https':
                is_https = True
            if is_https:
                https_urls.append(url)
            else:
                http_urls.append(url)

    # Domains all, blocked domains, for HTTPS and HTTP separately
    domains_list = record.findall('domain')
    if domains_list is not None:
        for domain in domains_list:
            domain = domain.text;
            domains.append(domain.encode('UTF8'))

            if is_ByDomain:
                blocked_domains.append(domain.encode('UTF8'))

            if is_https:
                https_domains.append(domain.encode('UTF8'))
            else:
                http_domains.append(domain.encode('UTF8'))

    # HTTP, HTTPS and blocked by IP separately
    ips = record.findall('ip')
    if ips is not None:
        for ip in ips:
            ip = ip.text

            if is_https:
                https_ips.append(ip)
            else:
                http_ips.append(ip)

            if is_ByIP:
                blocked_ips.append(ip)

    # For subnets same as IP addresses
    ipSubnets = record.findall('ipSubnet')
    if ipSubnets is not None:
        for ipSubnet in ipSubnets:
            ipSubnet = ipSubnet.text

            if is_https:
                https_ips.append(ipSubnet)
            else:
                http_ips.append(ipSubnet)

            if is_ByIP:
                blocked_ips.append(ipSubnet)


logging.info("HTTP URLs exported: %s" % len(set(http_urls)))
logging.info("HTTP IPs exported: %s" % len(set(http_ips)))
logging.info("HTTP domains exported: %s" % len(set(http_domains)))
logging.info("HTTPS URLs exported: %s" % len(set(https_urls)))
logging.info("HTTPS IPs exported: %s" % len(set(https_ips)))
logging.info("HTTPS domains exported: %s" % len(set(https_domains)))
logging.info("Totaly domains exported: %s" % len(set(domains)))
logging.info("Blocked IPs exported %s" % len(set(blocked_ips)))
logging.info("Blocked domains exported %s" % len(set(blocked_domains)))

https_with_blocked_domains = set(https_domains)|set(blocked_domains)
generate_zone_file(https_with_blocked_domains)
logging.info("Blocked domains with HTTPS domains exported %s" % 
    len(https_with_blocked_domains))

https_with_blocked_ips = set(https_ips)|set(blocked_ips)
generate_mikrotik_script(https_with_blocked_ips)
logging.info("Blocked IPs with HTTPs IPs exported %s" %
    len(https_with_blocked_ips))

""" Write parsed data to files
http_url.txt        - for check and DPI block
http_ip.txt         - for IP block (porblem URL)
http_domains.txt    - for DNS block (problem URL)
https_url.txt       - for check (not blocking)
https_ip            - for IP block (backup mode)
https_domains.txt   - for DNS block
domains.txt         - for statistic
blocked_ip.txt      - for IP block (type=ip)
blocked_domains.txt - for DNS block (type=domain)

"""

logging.info('Write parsed data to files')
write_parsed_data('http_url.txt', http_urls)
write_parsed_data('http_ip.txt', http_ips)
write_parsed_data('http_domains.txt', http_domains)
write_parsed_data('https_url.txt', https_urls)
write_parsed_data('https_ip.txt', https_ips)
write_parsed_data('https_domains.txt', https_domains)
write_parsed_data('domains.txt', domains)
write_parsed_data('blocked_ip.txt', blocked_ips)
write_parsed_data('blocked_domains.txt', blocked_domains)

if DNS_DIR:
    logging.info("Copy RPZ zone file")
    try:
        copy(DUMP_DIR + ZONE_FILE, DNS_DIR)
    except IOError as Err:
        logging.error(Err)
        exit(Err)

if WWW_DIR: 
    logging.info("Copy files to www root")
    try:
        copy(DUMP_DIR + MTIK_FILE, WWW_DIR)
        copy("%shttp_url.txt" % DUMP_DIR, WWW_DIR)
        copy("%shttps_url.txt" % DUMP_DIR, WWW_DIR)
        copy("%sblocked_domains.txt" % DUMP_DIR, WWW_DIR)
    except IOError as Err:
        logging.error(Err)
        exit(Err)

logging.info('Reloading RPZ')
try:
    call(['rndc', 'freeze', 'rpz.zone.'])
    call(['rndc', 'thaw', 'rpz.zone.'])
except OSError as Err:
    logging.error('Reload failed. ' + Err[1])

logging.info("--- Parsing stoped ---\n")