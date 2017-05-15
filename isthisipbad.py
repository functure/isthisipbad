#!/usr/bin/env python
# Name:     isthisipbad.py
# Purpose:  Checka IP against popular IP blacklist
# By:       Jerry Gamblin
# Date:     11.05.15
# Modified  11.05.15
# Rev Level 0.5
# -----------------------------------------------
# Downloaded from GitHub page:
# https://github.com/jgamblin/isthisipbad/blob/master/isthisipbad.py
# Modified by MJC to fix errors.

import os
import sys
import urllib
import urllib2
import argparse
import re
import socket
# Requires dnspython AKA python-dns package
import dns.resolver
from urllib2 import urlopen
import netaddr
import csv

def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def blink(text):
    return color(text, 5)


def green(text):
    return color(text, 32)


def blue(text):
    return color(text, 34)


def content_test(url, badip, func=None):
    """
    Test the content of url's response to see if it contains badip.
        Args:
            url -- the URL to request data from
            badip -- the IP address in question
        Returns:
            Boolean
    """
    if func:
        return func(url, badip)
    else:
        try:
            request = urllib2.Request(url)
            opened_request = urllib2.build_opener().open(request)
            html_content = opened_request.read()
            retcode = opened_request.code

            matches = retcode == 200
            matches = matches and re.findall(re.escape(badip), html_content)
            return len(matches) == 0
        except Exception, e:
            sys.stderr.write("%s - Error! %s\n" % (url, e))
            return True

CIDR_REGEX = re.compile("(([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2])) )")

def spamhaus_check(url, ip):
    try:
        request = urllib2.Request(url)
        opened_request = urllib2.build_opener().open(request)
        html_content = opened_request.read()
        retcode = opened_request.code
        all_cidr = [netaddr.IPNetwork(net[0]) for net in CIDR_REGEX.findall(html_content)]
        matches = retcode == 200
        return matches and not bool(sum([netaddr.IPAddress(ip) in net for net in all_cidr]))
    except Exception, e:
        sys.stderr.write("%s - Error! %s\n" % (url, e))
        return True


bls = ["b.barracudacentral.org", "bl.spamcannibal.org", "bl.spamcop.net",
       "blacklist.woody.ch", "cbl.abuseat.org", "cdl.anti-spam.org.cn",
       "combined.abuse.ch", "combined.rbl.msrbl.net", "db.wpbl.info",
       "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
       "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
       "dnsbl.sorbs.net", "drone.abuse.ch", "drone.abuse.ch",
       "duinv.aupads.org", "dul.dnsbl.sorbs.net", "dul.ru",
       "dyna.spamrats.com", "dynip.rothen.com",
       "http.dnsbl.sorbs.net", "images.rbl.msrbl.net",
       "ips.backscatterer.org", "ix.dnsbl.manitu.net",
       "korea.services.net", "misc.dnsbl.sorbs.net",
       "noptr.spamrats.com", "ohps.dnsbl.net.au", "omrs.dnsbl.net.au",
       "orvedb.aupads.org", "osps.dnsbl.net.au", "osrs.dnsbl.net.au",
       "owfs.dnsbl.net.au", "pbl.spamhaus.org", "phishing.rbl.msrbl.net",
       "probes.dnsbl.net.au", "proxy.bl.gweep.ca", "rbl.interserver.net",
       "rdts.dnsbl.net.au", "relays.bl.gweep.ca", "relays.nether.net",
       "residential.block.transip.nl", "ricn.dnsbl.net.au",
       "rmst.dnsbl.net.au", "smtp.dnsbl.sorbs.net",
       "socks.dnsbl.sorbs.net", "spam.abuse.ch", "spam.dnsbl.sorbs.net",
       "spam.rbl.msrbl.net", "spam.spamrats.com", "spamrbl.imp.ch",
       "t3direct.dnsbl.net.au", "tor.dnsbl.sectoor.de",
       "torserver.tor.dnsbl.sectoor.de", "ubl.lashback.com",
       "ubl.unsubscore.com", "virus.rbl.jp", "virus.rbl.msrbl.net",
       "web.dnsbl.sorbs.net", "wormrbl.imp.ch", "xbl.spamhaus.org",
       "zen.spamhaus.org", "zombie.dnsbl.sorbs.net"]



URLS = [
    #TOR
    ('TOR',
     'http://torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv',
     'is not a TOR Exit Node',
     'is a TOR Exit Node',
     False,
     None),

    #EmergingThreats
    ('EmergingThreats',
     'http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on EmergingThreats',
     'is listed on EmergingThreats',
     True,
     None),

    #AlienVault
    ('AlienVault',
     'http://reputation.alienvault.com/reputation.data',
     'is not listed on AlienVault',
     'is listed on AlienVault',
     True,
     None),

    #BlocklistDE
    ('BlocklistDE',
     'http://www.blocklist.de/lists/bruteforcelogin.txt',
     'is not listed on BlocklistDE',
     'is listed on BlocklistDE',
     True,
     None),

    #Dragon Research Group - SSH
    ('DragonResearch_SSH',
     'http://dragonresearchgroup.org/insight/sshpwauth.txt',
     'is not listed on Dragon Research Group - SSH',
     'is listed on Dragon Research Group - SSH',
     True,
     None),

    #Dragon Research Group - VNC
    ('DragonResearch_VNC',
     'http://dragonresearchgroup.org/insight/vncprobe.txt',
     'is not listed on Dragon Research Group - VNC',
     'is listed on Dragon Research Group - VNC',
     True,
     None),

    #OpenBLock
    ('OpenBlock',
     'http://www.openbl.org/lists/date_all.txt',
     'is not listed on OpenBlock',
     'is listed on OpenBlock',
     True,
     None),

    #NoThinkMalware
    ('NoThinkMalware',
     'http://www.nothink.org/blacklist/blacklist_malware_http.txt',
     'is not listed on NoThink Malware',
     'is listed on NoThink Malware',
     True,
     None),

    #NoThinkSSH
    ('NoThinkSSH',
     'http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
     'is not listed on NoThink SSH',
     'is listed on NoThink SSH',
     True,
     None),

    #Feodo
    ('Feodo',
     'http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
     'is not listed on Feodo',
     'is listed on Feodo',
     True,
     None),

    #antispam.imp.ch
    ('antispam.imp.ch',
     'http://antispam.imp.ch/spamlist',
     'is not listed on antispam.imp.ch',
     'is listed on antispam.imp.ch',
     True,
     None),

    #dshield
    ('dshield',
     'http://www.dshield.org/ipsascii.html?limit=10000',
     'is not listed on dshield',
     'is listed on dshield',
     True,
     None),

    #malc0de
    ('malc0de',
     'http://malc0de.com/bl/IP_Blacklist.txt',
     'is not listed on malc0de',
     'is listed on malc0de',
     True,
     None),

    #MalWareBytes
    ('MalwareBytes',
     'http://hosts-file.net/rss.asp',
     'is not listed on MalWareBytes',
     'is listed on MalWareBytes',
     True,
     None),

    #Spamhaus DROP (in CIDR format, needs parsing)
    ('Spamhaus_DROP',
     'https://www.spamhaus.org/drop/drop.txt',
     'is not listed on Spamhaus DROP',
     'is listed on Spamhaus DROP',
     False,
     spamhaus_check
     ),
    #Spamhaus EDROP (in CIDR format, needs parsing)
    ('Spamhaus_EDROP',
     'https://www.spamhaus.org/drop/edrop.txt',
     'is not listed on Spamhaus EDROP',
     'is listed on Spamhaus EDROP',
     False,
     spamhaus_check
     )]



class GeoParser:
    geo_regex = "(Country:\s(?P<country>.*))\n(State:\s(?P<state>.*))\n(City:\s(?P<city>.*))\n(Latitude:\s(?P<latitude>.*))\n(Longitude:\s(?P<longitude>.*))"

    @staticmethod
    def parse(geo):
        match = re.search(GeoParser.geo_regex, geo)
        return match.groupdict() if match else {}

def write_csv(rows):
    prefix_fields = ['ip', 'fqdn']
    geo_fields = ['country', 'state', 'city', 'coord']
    url_fields = [url[0] for url in URLS]
    bl_fields = bls
    suffix_fields = ['rep']
    keymap = prefix_fields + geo_fields + url_fields + bl_fields + suffix_fields

    writer = csv.DictWriter(sys.stdout, fieldnames=keymap)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Is This IP Bad?')
    parser.add_argument('-i', '--ip', help='IP address to check')
    parser.add_argument('--success', help='Also display GOOD', required=False, action="store_true")
    parser.add_argument('--output', '-o', choices=['csv', 'standard'], default='standard', help='Output format', required=False, action="store", dest='output')
    args = parser.parse_args()

    if args is not None and args.ip is not None and len(args.ip) > 0:
        badip = args.ip
        output_format = args.output
    else:
        my_ip = urlopen('http://icanhazip.com').read().rstrip()
        output_format = 'standard'

        print(blue('Check IP against popular IP and DNS blacklists'))
        print(blue('A quick and dirty script by @jgamblin\n'))
        print(red('Your public IP address is {0}\n'.format(my_ip)))

        # Get IP To Check
        resp = raw_input('Would you like to check {0} ? (Y/N):'.format(my_ip))

        if resp.lower() in ["yes", "y"]:
            badip = my_ip
        else:
            badip = raw_input(blue("\nWhat IP would you like to check?: "))
            if badip is None or badip == "":
                sys.exit("No IP address to check.")

    #IP INFO
    reversed_dns = socket.getfqdn(badip)
    geoip = urllib.urlopen('http://api.hackertarget.com/geoip/?q='
                           + badip).read().rstrip()

    if output_format == 'standard':
        print(blue('\nThe FQDN for {0} is {1}\n'.format(badip, reversed_dns)))
        print(red('Geolocation IP Information:'))
        print(blue(geoip))
        print('\n')
    elif output_format == 'csv':
        geo = GeoParser.parse(geoip)
        geo['coord'] = "{}-{}".format(geo.pop('latitude', ''), geo.pop('longitude', ''))

    BAD = 0
    GOOD = 0

    if output_format == 'csv':
        csv_d = dict(geo, fqdn=reversed_dns)

    for name, url, succ, fail, mal, func in URLS:
        if content_test(url, badip, func):
	    if args.success and output_format == 'standard':
                print(green('{0} {1}'.format(badip, succ)))
            elif output_format == 'csv':
                csv_d[name] = True
            GOOD = GOOD + 1
        else:
            if output_format == 'standard':
                print(red('{0} {1}'.format(badip, fail)))
            elif output_format == 'csv':
                csv_d[name] = False
            BAD = BAD + 1

    BAD = BAD
    GOOD = GOOD

    for bl in bls:
        try:
                my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(badip).split("."))) + "." + bl
                my_resolver.timeout = 5
                my_resolver.lifetime = 5
                answers = my_resolver.query(query, "A")
                answer_txt = my_resolver.query(query, "TXT")
                if output_format == 'standard':
                    print (red(badip + ' is listed in ' + bl)
                           + ' (%s: %s)' % (answers[0], answer_txt[0]))
                elif output_format == 'csv':
                    csv_d[bl] = False
                BAD = BAD + 1

        except dns.resolver.NXDOMAIN:
            if output_format == 'standard':
                print (green(badip + ' is not listed in ' + bl))
            elif output_format == 'csv':
                csv_d[bl] = True
            GOOD = GOOD + 1

        except dns.resolver.Timeout:
            if output_format == 'standard':
                print (blink('WARNING: Timeout querying ' + bl))
            elif output_format == 'csv':
                csv_d[bl] = True

        except dns.resolver.NoNameservers:
            if output_format == 'standard':
                print (blink('WARNING: No nameservers for ' + bl))
            elif output_format == 'csv':
                csv_d[bl] = True

        except dns.resolver.NoAnswer:
            if output_format == 'standard':
                print (blink('WARNING: No answer for ' + bl))
            elif output_format == 'csv':
                csv_d[bl] = True

    if output_format == 'standard':
        print(red('\n{0} is on {1}/{2} blacklists.\n'.format(badip, BAD, (GOOD+BAD))))
    elif output_format == 'csv':
        csv_d['ip'] = args.ip
        csv_d['fqdn'] = reversed_dns
        csv_d['rep'] = "{}/{}".format(BAD, GOOD+BAD)
        write_csv([csv_d])




