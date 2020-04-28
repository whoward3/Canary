"""
canary_shark_rnd
Description: The python script for the base canary service w/ random number of canaries deployed on bridges
Author: Winston Howard
Created Date: 02/25/20
 
 
Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import pyshark
import math
import time
import datetime
import subprocess
import re
import sys
import multiprocessing
import random
multiprocessing.set_start_method('spawn', True)

def evalutator(ip_dict, _log, bridge_id):
    """
    Evaluate the table and return 1 if window is flagged 
    """
    try:
     res = 0
     for ip in ip_dict:
       y = ip_dict[ip]
       p = (y)/50
       res += p*(math.log(p,2))
     res = 0 - res
     _log.put("\n@"+str(bridge_id) + ": " + 'Bridge Entropy: ' + str(res)+"\n@"+ str(bridge_id) + ": " + 'IP Table: ' + str(ip_dict)+"\n@"+ str(bridge_id) + ": " + 'Time: '+str(datetime.datetime.now())+"\n")
     if (res < 3.8):
       return 1
     return 0
    except Exception as e:
      print("+Evaluator Exception: " + str(e))

def reporter(_log, bridge_id):
    """
    Report that an attack is underway and cease canary operations
    TODO: Flag malicious IPs
    """
    _log.put("\n~"+str(bridge_id) + ": " + "THRESHOLD VIOLATED, TIME: " + str(datetime.datetime.now()))

def canary(interfaces, _log, bridge_id, time_delta):
    """
    Scans packets on a bridge based off the interfaces provided, does so for 5 minutes
    """
    stop_time = datetime.datetime.now() + datetime.timedelta(0,time_delta-30)
    warn_time = datetime.datetime.now() + datetime.timedelta(0,30)
    warn = True
    capture = pyshark.LiveCapture(interface=interfaces)
    ips_dict = {}
    count = 0
    flagCount = 0 
    for packet in capture.sniff_continuously():
      # close the _log queue if this canary has exceded the time_delta
      if datetime.datetime.now() > stop_time:
        _log.put("\n" + str(bridge_id) + ": Expected Stop Time: " + str(stop_time) + "\n" + str(bridge_id) + ": Actual Stop Time:   " + str(datetime.datetime.now()) + "\n")
        _log.close()
        return 0
      elif datetime.datetime.now() > warn_time and warn == True:
        print("~WARNING: OVER 30 SECONDS HAVE ELAPSED AND 0 GOOD PACKETS HAVE ARRIVED")

      try:
        d_ip = packet['ip'].dst
        s_ip = packet['ip'].src
        _log.put("\n"+str(bridge_id) + ": " + 'Destination: ' + d_ip+"\n"+ str(bridge_id) + ": " + 'Source: ' + s_ip+"\n"+ str(bridge_id) + ": " + 'Time: '+str(datetime.datetime.now())+"\n")    
        warn = False
        if not d_ip in ips_dict:
          ips_dict[d_ip] = 1
        else:
          ips_dict[d_ip] += 1 
        count += 1
        if count == 50:
          flagCount += evalutator(ips_dict,_log,bridge_id)
          count = 0
          ips_dict = {}
        if flagCount > 5:
          # 5 windows of 50 packets > entropy threshold, attack is underway
          reporter(_log,bridge_id)      
          flagCount = 0  
      except Exception:
       pass

def set_canaries():
    """
    Gather the interfaces for each bridge, then spawn an canary proccess for each bridge
    """
    # check=true is key to ensure python raises an exception here instead of piping bad data to our canaries
    bridge_call = subprocess.run(["brctl","show"], stdout=subprocess.PIPE, text=True, check=True)
    splitList = list(re.split('\n|\t',bridge_call.stdout))
    interface_list = []
    bridge_list = []
    for item in splitList:
    # if its a new bridge, save old bridge to interface_list & wipe the bridge_list for new bridge
      if(item.find("b.",0,2) is not -1):
        interface_list.append(bridge_list)
        bridge_list = []
    # if its an interface, add it to the bridges list
      elif(item.find("veth",0,4) is not -1 ):
        bridge_list.append(item)
    # save the last bridge
    interface_list.append(bridge_list)

    return interface_list
  
def show_status(time_delta):
    """
    Iterate through time delta and show progress in console
    """
    for i in range(time_delta):  
     time.sleep(1)
     printProgressBar(i + 1, time_delta, prefix = 'Project Canary Trial Progress:', suffix = 'Complete', length = 50)

def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar, Ref: https://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()

if __name__ == '__main__':
   _log = multiprocessing.Queue()
   interface_list = set_canaries()
   processes = []

   # create random sequence to deploy a canary with 50% probability
   random_list = []
   numCanaries = 0
   for bridge in interface_list:
     if bridge:
       probability = random.randint(1,2)
       if(probability == 1):
         numCanaries += 1
       random_list.append(probability)

   if len(interface_list) < 2:
    print("No CORE Bridges found, ensure the network_initalizer executed correctly")
    exit() 
   else:
     header = "CANARY REPORT: {} Bridges, {} Canaries, {} Nodes \nBridge : Traffic : Time".format(len(interface_list)-1,numCanaries,(len(interface_list)-1)*5)
     _log.put(header)
   
   # for each bridge, pass its interface list to a canary process and kick it off for the time_delta
   time_delta = 330
   bridge_id = 0
   i = -1
   for bridge in interface_list:
    if bridge:
      # randomly deploy a canary with 50% propability
      i+=1
      if(random_list[i] == 1):
       bridge_id += 1
       p = multiprocessing.Process(target=canary, args=(bridge, _log, bridge_id, time_delta))
       processes.append(p)
       print("Started Canary " + str(p.name) + " on " + str(bridge))
       p.start()

   # let time_delta elapse before gathering _logs, allow child processes to terminate, then dump the log
   show_status(time_delta)
   name = "../coreReports/CANARY_LOG_"+str(datetime.datetime.now())
   file = open(name,"w")
   print("Writing report...\r")
   while not _log.empty():
      file.write(_log.get())
   file.close()

   # finish each canary process
   for p in processes:
     p.join()
     print("Finished Canary " + str(p.name))