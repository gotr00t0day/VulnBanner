#!/usr/bin/python3

import socket 
import os, sys
import threading

# Vulnerable banner detection script

ip = "10.0.0.221"

def getbanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sck.connect((ip,port))
        banner = sck.recv(1024)
        return banner
    except:
        return

def vulncheck(banner, filename):
    f = open(filename, "r")
    for line in f.readlines():
        if line.strip("\n").encode() in banner:
            print ("Vulnerable: {}".format(banner.strip(b"\n\r")))
    
def main():
    if len(sys.argv) == 2:
        filename = sys.argv[1]
        if not os.path.isfile(filename):
            print ("File doesn't exist")
            exit(0)
        if not os.access(filename, os.R_OK):
            print ("Access Denied")
            exit(0)
    else:
        print ("Usage: " + str(sys.argv[0]) + " File.txt")
        exit(0)
    for port in range(1,80):
        banner = getbanner(ip, port)
        if banner:
            print ("{}/{} : {}".format(ip, port, banner))
            vulncheck(banner, filename)
    t = threading.Thread(target=getbanner, args=(ip, port))
    t.start()

main()
