# This file continuously reads alerts.txt
# and keeps track of signatures, which should be
# sent to SENSS. If an older signature is not useful
# anymore, e.g., because the newer signature is better,
# it deletes it and sends a more useful signature.
import time, sys, os

signatures = []

class Signature:
    
    def __init__(self, line):
        self.src = None
        self.sport = None
        self.dst = None
        self.dport = None
        self.proto = None
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
        return "src ip ", self.src, " and src port ", self.sport, " and dst ip ", self.dst, " and dst port ", self.dport, " and proto ", self.proto

def insertSignature(sig):
    siglist = signatures
    for s in siglist:
        if (sig == s):
            return
        if (sig.contains(s)):
            signatures.remove(s)
            return
            #decide which is better 
            #if sig
            #  delete s
            #  insert sig if not there already
            #else return
        elif(s.contains(sig)):
            return
            #decide which is better 
            #if sig
            #  delete s
            #  insert sig if not there already
            #else return
        else:
            pass    
    # We came here because this sig is like none other
    # insert it
    signatures.append(sig)
        
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

def processalert(line):
# 0 1449680158 START 497 18315152 8456 src ip 23.45.32.0 and dst ip 0.0.0.0 and proto tcp
    items = line.split()
    oci = items[5]
    s = Signature(line)
    print line
    insertSignature(s)
    for ss in signatures:
        print "Signature ",ss.printsig()
    print "\n\n\n\n\n\n";
        
# Alert file is specified on the cmd line        
if __name__ == '__main__':
    loglines = follow(sys.argv[1])
    for line in loglines:
        processalert(line)
