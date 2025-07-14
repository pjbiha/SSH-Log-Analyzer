#import argparse to parse command-line arguments
import argparse
#import re for regular expressions
import re
#import datetime utilities for timestamp handling
from datetime import datetime, timedelta
#import defaultdict and deque from collections for efficient structures
from collections import defaultdict, deque
#import Path from pathlib to work with filesystem paths
from pathlib import Path
#import typing helpers for type annotations
from typing import Deque, Dict, List, Tuple

#compile a regular expression to match failed SSH login lines
FAILED_RE = re.compile(
    r"""
    ^                                     #start of line
    (?P<month>\w{3})\s+                  #month
    (?P<day>\d{1,2})\s+                  #day
    (?P<time>\d{2}:\d{2}:\d{2})\s+       #time hours:minutes:seconds
    \S+\s+                               #hostname
    sshd\[\d+\]:\s+                      #process tag
    Failed\spassword\sfor\s(?:invalid\suser\s)?
    .*?from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})    #IPv4 address
    """,
    re.VERBOSE,     #ignores comments and space characters
)
  
#Map month abbreviations to integers
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

#convert the log timestamp fragments into a datetime object
def parse_timestamp(month: str, day: str, time_: str, year: int) -> datetime:
    hour, minute, second = map(int, time_.split(":"))
    #return the assembled datetime
    return datetime(year, MONTHS[month], int(day), hour, minute, second)

#load failed login events from the log file
def load_fail_events(
    log_path: Path,
    year: int,
) -> List[Tuple[datetime, str]]:
    #initialize an empty list to store events
    events: List[Tuple[datetime, str]] = []
    #open the log file with UTF-8 encoding
    with log_path.open("r", encoding="utf-8", errors="ignore") as fh:
        #iterate over every line in the file
        for line in fh:
            #attempt to match the regex
            match = FAILED_RE.search(line)
            #if there isn't a match it skips the line
            if match is None:
                continue
            #parse the timestamp into a datetime
            ts = parse_timestamp(match["month"], match["day"], match["time"], year)
            #append the event to the list
            events.append((ts, match["ip"]))
    #return all the collected events
    return events

#detects brute-force activity by counting failures per IP in a sliding window
def detect_bruteforce(
    events: List[Tuple[datetime, str]],
    fails: int,
    window: int,
) -> Dict[str, int]:
    #dictionary for offending ip addresses
    offenders: Dict[str, int] = {}
    #dictionary mapping ip to deque of recent timestamps
    buckets: Dict[str, Deque[datetime]] = defaultdict(deque)
    #timedelta representing the sliding window
    delta = timedelta(minutes=window)

    #iterate through each failure event
    for ts, ip in events:
        #retrieve or create the deque for this ip
        q = buckets[ip]
        #append current timestamp
        q.append(ts)
        #remove timestamps outside the sliding window
        while q and ts - q[0] > delta:
            q.popleft()
        #record offender if it meets or exceeds the threshold
        if len(q) >= fails:
            offenders[ip] = len(q)
    #return the offenders dictionary
    return offenders

#print report of offenders
def print_report(offenders: Dict[str, int]) -> None:
    #if there are no offenders
    if not offenders:
        print("There was no brute-force activity detected.")
        return
    #print header
    print("  Brute-force offenders:")
    print("-------------------------")
    #sort offenders by descending count
    for ip, count in sorted(offenders.items(), key=lambda x: x[1], reverse=True):
        #print each offending IP with its failure count
        print(f"{ip:<15}  {count} failed logins")

def main() -> None:

    parser = argparse.ArgumentParser(
        add_help=False,                  
        description=None              
    )


    parser.add_argument("logfile", type=Path)


    parser.add_argument("--fails",  type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--year",   type=int,
                        default=datetime.now().year)

    #parse CLI
    args = parser.parse_args()

    events    = load_fail_events(args.logfile, args.year)
    offenders = detect_bruteforce(events, args.fails, args.window)
    print_report(offenders)

if __name__ == "__main__":
    main()
