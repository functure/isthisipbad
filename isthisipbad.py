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
import multiprocessing
import multiprocessing.pool
import traceback

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


def content_test(url, ip_list, func=None):
    """
    Test the content of url's response to see if it contains badip.
        Args:
            url -- the URL to request data from
            badip -- the IP address in question
        Returns:
            Boolean
    """
    if func:
        return func(url, ip_list)
    else:
        try:
            request = urllib2.Request(url)
            opened_request = urllib2.build_opener().open(request)
            html_content = opened_request.read()
            retcode = opened_request.code

            if retcode != 200:
                raise Exception('Retcode: {}'.format(retcode))
            else:
                ret = []
                for badip in ip_list:
                    matches = re.findall(re.escape(badip), html_content)
                    ret.append(len(matches) == 0)
                return ret
        except Exception, e:
            traceback.print_exc()
            sys.stderr.write("%s - Error! %s\n" % (url, e))
            return [True]*len(ip_list)

CIDR_REGEX = re.compile("(([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2])) )")

def spamhaus_check(url, ip_list):
    try:
        request = urllib2.Request(url)
        opened_request = urllib2.build_opener().open(request)
        html_content = opened_request.read()
        retcode = opened_request.code
        all_cidr = [netaddr.IPNetwork(net[0]) for net in CIDR_REGEX.findall(html_content)]
        if retcode != 200:
            raise Exception('Retcode: {}'.format(retcode))
        else:
            ret = []
            for badip in ip_list:
                matches = re.findall(re.escape(badip), html_content)
                ret.append(not bool(sum([netaddr.IPAddress(ip) in net for net in all_cidr])))
            return ret
    except Exception, e:
        traceback.print_exc()
        sys.stderr.write("%s - Error! %s\n" % (url, e))
        return [True]*len(ip_list)


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


def check_ip_bl(ip_bl):
    badip, bl = ip_bl
    try:
        my_resolver = dns.resolver.Resolver()
        query = '.'.join(reversed(str(badip).split("."))) + "." + bl
        my_resolver.timeout = 5
        my_resolver.lifetime = 5
        answers = my_resolver.query(query, "A")
        answer_txt = my_resolver.query(query, "TXT")

        return False, (red(badip + ' is listed in ' + bl) + ' (%s: %s)' % (answers[0], answer_txt[0]))

    except dns.resolver.NXDOMAIN:
        return True, (green(badip + ' is not listed in ' + bl))
        #GOOD = GOOD + 1

    except dns.resolver.Timeout:
        return True, (blink('WARNING: Timeout querying ' + bl))

    except dns.resolver.NoNameservers:
        return True, (blink('WARNING: No nameservers for ' + bl))

    except dns.resolver.NoAnswer:
        return True, (blink('WARNING: No answer for ' + bl))


parser = argparse.ArgumentParser(description='Is This IP Bad?')
input_parser = parser.add_mutually_exclusive_group(required=True)
input_parser.add_argument('-i', '--ip', nargs='*', help='IP address to check', action='store', dest='ip')
input_parser.add_argument('-', '--stdin', help='Get IP addresses from stdin CTRL+D to stop (EOF)', action='store_true')
parser.add_argument('--success', help='Also display GOOD', required=False, action="store_true")
parser.add_argument('--output', '-o', choices=['csv', 'standard'], default='standard', help='Output format', required=False, action="store", dest='output')


if __name__ == "__main__":
    args = parser.parse_args()

    output_format = args.output
    if args.ip:
        ip_list = args.ip
    elif args.stdin:
        ip_list = []
        for line in sys.stdin:
            ip_list.append(line.strip())
    else:
        my_ip = urlopen('http://icanhazip.com').read().rstrip()
        output_format = 'standard'

        print(blue('Check IP against popular IP and DNS blacklists'))
        print(blue('A quick and dirty script by @jgamblin\n'))
        print(red('Your public IP address is {0}\n'.format(my_ip)))

        # Get IP To Check
        resp = raw_input('Would you like to check {0} ? (Y/N):'.format(my_ip))

        if resp.lower() in ["yes", "y"]:
            ip_list = [my_ip]
        else:
            badip = raw_input(blue("\nWhat IP would you like to check?: "))
            if badip is None or badip == "":
                sys.exit("No IP address to check.")
            else:
                ip_list = [badip]

    results = dict([(ip, {'good': 0, 'bad': 0}) for ip in ip_list])
    #IP INFO
    for badip in ip_list:
        reversed_ = socket.getfqdn(badip)
        geo_ = urllib.urlopen('http://api.hackertarget.com/geoip/?q='
                           + badip).read().rstrip()

        if output_format == 'standard':
            print(blue('\nThe FQDN for {0} is {1}\n'.format(badip, reversed_)))
            print(red('Geolocation IP Information for {0}:'.format(badip)))
            print(blue(geo_))
            print('\n')
        elif output_format == 'csv':
            geo = GeoParser.parse(geo_)
            geo['coord'] = "{},{}".format(geo.pop('latitude', ''), geo.pop('longitude', ''))
            results[badip].update(geo, fqdn=reversed_)


    for name, url, succ, fail, mal, func in URLS:
        ret = content_test(url, ip_list, func)
        for i in range(len(ret)):
            badip = ip_list[i]
            if ret[i]:
                if args.success and output_format == 'standard':
                    print(green('{0} {1}'.format(badip, succ)))
                elif output_format == 'csv':
                    results[badip].update({name: True})
                results[badip]['good'] += 1
            else:
                if output_format == 'standard':
                    print(red('{0} {1}'.format(badip, fail)))
                elif output_format == 'csv':
                    results[badip].update({name: False})
                    csv_d[name] = False
                results[badip]['bad'] += 1

    ip_bl_map = []
    for ip in ip_list:
        for bl in bls:
            ip_bl_map.append((ip,bl))

    p = multiprocessing.pool.ThreadPool(len(bls))
    ret = p.map(check_ip_bl, ip_bl_map)
    for i in xrange(len(ret)):
        good, msg = ret[i]
        ip, bl = ip_bl_map[i]
        if output_format == 'standard':
            if not good or args.success:
                print msg
        else:
            results[ip][bl] = good
        if good:
            results[ip]['good'] += 1
        else:
            results[ip]['bad'] += 1

    csv_list = []
    for ip, val in results.iteritems():
        if output_format == 'standard':
            print(red('\n{0} is on {1}/{2} blacklists.\n'.format(ip, val['bad'], val['good']+val['bad'])))
        elif output_format == 'csv':
            bad = val.pop('bad')
            good = val.pop('good')
            csv_d = dict(val, ip=ip, rep="{}/{}".format(bad, good+bad))
            csv_list.append(csv_d)
    write_csv(csv_list)


