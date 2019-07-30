# This file continuously reads alerts.txt
# and keeps track of signatures, which should be
# sent to SENSS. If an older signature is not useful
# anymore, e.g., because the newer signature is better,
# it deletes it and sends a more useful signature.
import time, sys, os, argparse

targets = dict()
limit = 0
duration = 0
count = 0
curtime = None
changed = False
printed = []

class Target:
    def __init__(self, ip):
        self.ip = ip
        self.signatures = []
        
class Signature:
    
    def __init__(self, line):
        self.time = None
        self.src = None
        self.sport = None
        self.dst = None
        self.dport = None
        self.proto = None
        self.samples = 1
        self.votes = 1
        self.start = 0
        self.end = 0
        ar = line.split()
        self.time = int(ar[1])
        self.start = self.end = self.time
        self.rate = int(ar[4])*8/1000000000.0;
        self.oci = int(ar[5])
        self.new = True
        for delim in ("src ip", "src port", "dst ip", "dst port", "proto"):
            i = line.find(delim)
            if (i > -1):
                j = line.find(" ", i+len(delim)+1)
                arg = line[i+len(delim)+1:j]
                if (delim == "src ip"):
                  self.src = arg
                elif (delim == "src port"):
                    self.sport = arg
                elif (delim == "dst ip"):
                    self.dst = arg
                elif (delim == "dst port"):
                    self.dport = arg
                elif (delim == "proto"):
                    self.proto = arg

    def __eq__(self, other):
        return (self.src == other.src) and (self.sport == other.sport) and (self.dst == other.dst) and (self.dport == other.dport)

    def __ne__(self, other):
        return not self.__eq__(other)

    def contains(self,s):
        if ((self.src == "0.0.0.0" or self.src == None or self.src == s.src) and
            (self.sport == None or self.sport == s.sport) and
            (self.dst == "0.0.0.0" or self.dst == None or self.dst == s.dst) and
            (self.dport == None or self.dport == s.dport) and
            (self.proto == s.proto)):
            return True
        else:
            return False


    def printsig(self):
        dur = self.end - self.start
        output = str(curtime)+ " "+str(self.votes)+ " time "+str(self.time) + " rate " + str(round(self.rate,3)) + " Gbps, " + str(round(self.oci/1000)) +  " Kpps, duration " + str(dur) + " seconds, signature:  "
        if (self.src != "0.0.0.0" and self.src is not None):
            output += " src ip " + self.src
        if (self.sport is not None):
            output += " src port " + str(self.sport)
        if (self.dst != "0.0.0.0" and self.dst is not None):
            output += " dst ip " + self.dst
        if (self.dport is not None):
            output += " dst port " + str(self.dport)
        if (self.proto is not None):
            output += " and proto " + self.proto
        return output

def printSigList(time):
    global changed
    changed = False
    for t in targets:
        for ss in targets[t].signatures:
            if ss.votes >= duration and ss.rate >= limit:
                if ss not in printed:
                    print "Signature ",ss.printsig()
                    printed.append(ss)

                    

def insertSignature(sig, time, limit):
    global changed

    if (sig.dst not in targets.keys()):
        if sig.rate >= limit:
            targets[sig.dst] = Target(sig.dst)
            targets[sig.dst].signatures.append(sig)
            #print "Append sig 1 ",sig.printsig()
            changed = True
        else:
            return
    else:
        siglist = targets[sig.dst].signatures
        #print "Target ",sig.dst, " signatures ", len(siglist)
        for s in siglist:
            if (sig == s):
                s.votes += 1
                if (s.rate < sig.rate):
                    s.rate = sig.rate
                    s.oci = sig.oci
                s.samples += 1
                s.end = sig.end
                return
            if (sig.contains(s)):
                if (sig.rate > s.rate and sig.rate >= limit):
                    targets[sig.dst].signatures.remove(s)
                    #print "Append sig 2 ",sig.printsig()                
                    targets[sig.dst].signatures.append(sig)
                    changed = True
                return
            elif(s.contains(sig)):
                return
        if(sig.rate >= limit):
            #print "Append sig 3 ",sig.printsig()
            targets[sig.dst].signatures.append(sig)
            changed = True
        return
    
# Continuously read from the alert file
def follow(name):
    current = open(name, "r")
    curino = os.fstat(current.fileno()).st_ino
    while True:
        while True:
            line = current.readline()
            if not line:
                break
            yield line

        try:
            if os.stat(name).st_ino != curino:
                new = open(name, "r")
                current.close()
                current = new
                curino = os.fstat(current.fileno()).st_ino
                continue
        except IOError:
            pass
        time.sleep(1)

def processalert(line, spec, noscan):
# 0 1449680158 START 497 18315152 8456 src ip 23.45.32.0 and dst ip 0.0.0.0 and proto tcp
    global count
    global curtime
    items = line.split()
    time = items[1]
    if curtime is None:
        curtime = time
    oci = items[5]
    s = Signature(line)
    if (time > curtime):
        curtime = time
    if (spec and (s.dst == "0.0.0.0" or s.dst == None) and (s.src == "0.0.0.0" or s.src == None) and s.dport == None):
        return
    if (noscan and s.proto == "tcp" and s.dport != None):
        return
    insertSignature(s, time, limit)
    if changed:
        printSigList(time)
            #if ss.votes < 0.1:
            #    targets[t].signatures.remove(ss)

        
# Alert file is specified on the cmd line        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("alertfile", help="Alert file generated by amon-senss program")
    parser.add_argument("minvol", help="Min Gpbs volume an attack should have to result in an alert")
    parser.add_argument("-s", "--spec", help="Display only alerts that have IP or dst port", action="store_true")
    parser.add_argument("-n", "--noscan", help="Try to detect and exclude scan campaigns", action="store_true")
    parser.add_argument("-d", "--duration", help="How many seconds does the alert have to persist to display it to an operator", type=int)

    args = parser.parse_args()

    loglines = follow(args.alertfile)
    limit = float(args.minvol)
    spec = False
    noscan = False
    if (args.duration):
        duration = args.duration
    if (args.spec):
        spec = True
    if (args.noscan):
        noscan = True
    print "Duration ",duration
    for line in loglines:
        processalert(line, spec, noscan)
