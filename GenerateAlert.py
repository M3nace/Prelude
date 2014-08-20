#!/usr/bin/env python3

"""
Generate alert and store them in a CSV file, formated like :
"target", "source", "classification", "analyzer", "date",
   ^         ^            ^               ^         ^
   |         |            |               |         |
   |         |            |               |         --------- The date of the alert, format : DD/MM/YYYYTHH:MM
   |         |            |               |
   |         |            |               ------------------- Analyzer name, which create the alert
   |         |            |
   |         |            ----------------------------------- Type of the alert
   |         |
   |         ------------------------------------------------ IP of the device which create the alert
   |
   ---------------------------------------------------------- IP of the device which has been targeted

Contiguous IP are generated with the function ipRange(start, end), to simulate a targeted network.
Where "start" is the first IP in the range and "end", the last. Both type are strings.
E.g. : ipRange("192.168.1.0", "192.168.1.5") will return a list including :
[ "192.168.1.0", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5" ]

Random date are generated with the function randomDate(start, end), to simulate attacks on a period of time.
Where "start" is the beginning of a period, and "end", the end of it. Both type are datetime.

IP Source are randomly generated and stored in a list.
Classification and analyzer are randomly picked from an established list. Lazy, I know.

And finally, the CSV is written, line by line, picking a "random" settings each loop. "Random" because
the random module should be called "pseudo-random":
> Generate 5000 alerts.
> You have a list of 5 analyzers.
> You will have a CSV where each analyzer appears around 1000 times.
> That's not a place to talk about that.
"""

import os
import sys
import random
import csv
import json
import time
from datetime import timedelta
from datetime import datetime
from random import randint

# How many IP source do you want ?
nb_ip_source = 5
# How many alert (line in the CSV file) do you want ? /!\ The higher, the harder to compute (for the diagram) /!\
nb_alert = 5000

def ipRange(start_ip, end_ip):
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = []

   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))

   return ip_range


def randomDate(start, end):
   return (start + timedelta(seconds=randint(0, int((end - start).total_seconds())))).strftime('%d/%m/%YT%H:%M')#.date()


def main(argv=None):
   target_list = ipRange("10.10.10.1", "10.10.10.20")
   source_list = [ ]
   classification_list = [ "SSH Failed", "Bruteforce", "DDoS", "Eth. Sniffing", "Buffer overflow" ]
   analyzer_list = [ "Prelude-LML", "Suricata", "OSSEC", "Samhain", "Snort" ]
   date_begin = datetime.strptime("01 Jan 00", "%d %b %y")
   date_end = datetime.strptime("31 Dec 14", "%d %b %y")
   # We list the index here, to write it on the first line of the CSV file
   indexes = ["target", "source", "classification", "analyzer", "date"]

   for j in range(nb_ip_source):
      source_list.append('.'.join('%s'%random.randint(0, 255) for i in range(4)))

   with open('alert.csv', 'w') as csvfile:
      spamwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
      spamwriter.writerow(indexes)
      for i in range(nb_alert):
         spamwriter.writerow([random.choice(target_list),
                              random.choice(source_list),
                              random.choice(classification_list),
                              random.choice(analyzer_list),
                              randomDate(date_begin, date_end)])

   return 0

if __name__=="__main__":
   status = main()
   sys.exit(status)
