#!/usr/bin/env python

"""
CSVReader - Read a data.cvs GeoIP format file and store it in a dictionary
The CVS format parsed must match the GeoIPCountryWhoIs.cvs :
"IP Start", "IP End", "IP Start INT format", "IP End INT format", "Short Name", "Range Name"
    -> IP Start/End : the first/last ip of the range
    -> IP Start/End INT format : Same as IP start, but in int format (see below)
    -> Short Name : Abreviation for the range name
    -> Range Name : Full range Name
Example : "192.168.1.0", "192.168.1.255", "3232235776", "3232236031", "SN", "Small Network"

IP int calculation :
(first octet * 256^3) + (second octet * 256^2) + (third octet * 256) + (fourth octet)
For 192.168.1.0 :
    (192 * 256^3) + (168 * 256^2) + (1 * 256) + (0)
<=> 3221225472 + 11010048 + 256
<=> 3232235776

The dictionary keys are the tuple (Range Name, Short Name)
The items are a list of as many tuple as IP range for the key
Example :
(Private Network, PN)
[
    ("10.0.0.0", "10.255.255.255", "167772160", "184549375"),
    ("172.16.0.0", "172.31.255.255", "2886729728", "2887778303"),
    ("192.168.0.0", "192.168.255.255", "3232235520", "3232301055")
]

(My Network, MN) [("127.3.0.0", "127.3.255.255", "2130903040", "2130968575")]
"""

import csv
import collections

class CSVReader:
    def __init__(self, csv_file):
        self.csv_file = csv_file
        self.db = { }

    def parse_file(self):
        with open(self.csv_file, 'r') as fd:
            reader = csv.reader(fd)
            for row in reader:
                ip_start, ip_end, ipint_start, ipint_end, short_name, range_name = row
                if (range_name, short_name) in self.db:
                    self.db[(range_name, short_name)] += [(ip_start, ip_end, ipint_start, ipint_end)]
                else:
                    self.db[(range_name, short_name)] = [(ip_start, ip_end, ipint_start, ipint_end)]

        self.db = collections.OrderedDict(sorted(self.db.items()))

    def delete(self, range_name):
        if range_name in self.db:
            del self.db[range_name]

    def create(self, range_name):
        self.db[range_name] = None

    def insert_ip(self, range_name, value):
        if range_name in self.db:
            self.db[range_name] += value
        else:
            self.db[range_name] = value

    def write_csv(self):
        with open(self.csv_file, 'wb') as fd:
            writer = csv.writer(fd, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
            for key, ip_lists in self.db.iteritems():
                for ip_range in ip_lists:
                    ip_start, ip_end, int_start, int_end = ip_range
                    range_name, range_short = key
                    writer.writerow([ip_start, ip_end, int_start, int_end, range_short, range_name])

    def get_range(self):
        return self.db.keys()

    def get_ip_from_range(self, range_name):
        if range_name in self.db:
            return self.db[range_name]
        else:
            return [ ]

    def get_whole_db(self):
        return self.db
