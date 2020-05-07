"""
canary_shark
Description: The python script for the base canary service using pyshark
Author: Winston Howard
Created Date: 01/14/20


Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import math
import time
import datetime
import subprocess
import random
import re
import sys
import getopt
import multiprocessing
import pyshark
multiprocessing.set_start_method('spawn', True)


class CanaryShark():

    @classmethod
    def evalutator(self, ip_dict, _log, bridge_id, thresh):
        """
        Evaluate the table and return 1 if window is flagged
        """
        try:
            res = 0
            for ip in ip_dict:
                y = ip_dict[ip]
                p = (y) / 50
                res += p * (math.log(p, 2))
            res = 0 - res
            _log.put("\n@" +
                     str(bridge_id) +
                     ": " +
                     'Bridge Entropy: ' +
                     str(res) +
                     "\n@" +
                     str(bridge_id) +
                     ": " +
                     'IP Table: ' +
                     str(ip_dict) +
                     "\n@" +
                     str(bridge_id) +
                     ": " +
                     'Time: ' +
                     str(datetime.datetime.now()) +
                     "\n")
            if (res < thresh):
                return 1
            return 0
        except Exception as e:
            print("+Evaluator Exception: " + str(e))

    @classmethod
    def reporter(self, _log, bridge_id):
        """
        Report that an attack is underway and cease canary operations
        """
        _log.put("\n~" +
                 str(bridge_id) +
                 ": " +
                 "THRESHOLD VIOLATED, TIME: " +
                 str(datetime.datetime.now()))

    @classmethod
    def canary(self, interfaces, _log, bridge_id, time_delta, threshold):
        """
        Scans packets on a bridge based off the interfaces provided, does so for 5 minutes
        """
        stop_time = datetime.datetime.now() + datetime.timedelta(0, time_delta - 30)
        warn_time = datetime.datetime.now() + datetime.timedelta(0, 45)
        warn = True
        capture = pyshark.LiveCapture(interface=interfaces)
        ips_dict = {}
        count = 0
        flag_count = 0
        for packet in capture.sniff_continuously():
            # close the _log queue if this canary has exceded the time_delta
            if datetime.datetime.now() > stop_time:
                _log.put("\n" +
                         str(bridge_id) +
                         ": Expected Stop Time: " +
                         str(stop_time) +
                         "\n" +
                         str(bridge_id) +
                         ": Actual Stop Time:   " +
                         str(datetime.datetime.now()) +
                         "\n")
                _log.close()
                return 0
            elif datetime.datetime.now() > warn_time and warn == True:
                print("~CANARY {} WARNING: OVER 45 SECONDS HAVE ELAPSED AND 0 VALID PACKETS HAVE ARRIVED".format(
                    bridge_id))

            try:
                d_ip = packet['ip'].dst
                s_ip = packet['ip'].src
                _log.put("\n" +
                         str(bridge_id) +
                         ": " +
                         'Destination: ' +
                         d_ip +
                         "\n" +
                         str(bridge_id) +
                         ": " +
                         'Source: ' +
                         s_ip +
                         "\n" +
                         str(bridge_id) +
                         ": " +
                         'Time: ' +
                         str(datetime.datetime.now()) +
                         "\n")
                warn = False
                if not d_ip in ips_dict:
                    ips_dict[d_ip] = 1
                else:
                    ips_dict[d_ip] += 1
                count += 1
                if count == 50:
                    flag = CanaryShark.evalutator(
                        ips_dict, _log, bridge_id, threshold)
                    # If we didn't flag this window reset the flagCount to 0
                    if(flag == 0):
                        flag_count = 0
                    else:
                        flag_count += flag
                    count = 0
                    ips_dict = {}
                if flag_count == 5:
                    # 5 consecutive windows of 50 packets < entropy threshold,
                    # attack is underway
                    CanaryShark.reporter(_log, bridge_id)
                    flag_count = 0
            except Exception:
                pass

    @classmethod
    def set_canaries(self):
        """
        Gather the interfaces for each bridge, then spawn an canary proccess for each bridge
        """
        # check=true is key to ensure python raises an exception here instead
        # of piping bad data to our canaries
        bridge_call = subprocess.run(
            ["brctl", "show"], stdout=subprocess.PIPE, text=True, check=True)
        splitList = list(re.split('\n|\t', bridge_call.stdout))
        interface_list = []
        bridge_list = []
        for item in splitList:
            # if its a new bridge, save old bridge to interface_list & wipe the
            # bridge_list for new bridge
            if(item.find("b.", 0, 2) is not -1):
                interface_list.append(bridge_list)
                bridge_list = []
        # if its an interface, add it to the bridges list
            elif(item.find("veth", 0, 4) is not -1):
                bridge_list.append(item)
        # save the last bridge
        interface_list.append(bridge_list)

        return interface_list

    @classmethod
    def show_status(self, time_delta):
        """
        Iterate through time delta and show progress in console
        """
        for i in range(time_delta):
            time.sleep(1)
            CanaryShark.printProgressBar(
                i + 1,
                time_delta,
                prefix='Project Canary Trial Progress:',
                suffix='Complete',
                length=50)

    @classmethod
    def printProgressBar(self, iteration, total, prefix='',
                         suffix='', decimals=1, length=100, fill='█', printEnd="\r"):
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
        percent = ("{0:." + str(decimals) + "f}").format(100 *
                                                         (iteration / float(total)))
        filled_len = int(length * iteration // total)
        bar = fill * filled_len + '-' * (length - filled_len)
        print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end=printEnd)
        # Print New Line on Complete
        if iteration == total:
            print()

    @classmethod
    def main(self, argv):
        """
        The main function that checks for optional command line options
        """
        # create essential process variables
        _log = multiprocessing.Queue()
        interface_list = CanaryShark.set_canaries()
        processes = []
        bridges = len(interface_list) - 1

        # check for optional parameters
        args = []
        threshold = 3.5
        num_canaries = bridges
        attackers = []
        label = "_"

        try:
            opts, args = getopt.getopt(
                argv, "ht:n:a:l:", [
                    "threshold=", "numcanaries=", "attackers=", "label="])
        except getopt.GetoptError:
            print('Error: expected canary_shark.py -t <entropy threshold> -n <number of canaries> -a <list of attackers> -l <report label>')
            if(args):
                print(args)
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                print(
                    'canary_shark.py -t <entropy threshold> -n <number of canaries> -a <list of attackers> -l <report label>')
                sys.exit()
            elif opt in ("-t", "--threshold"):
                threshold = arg
            elif opt in ("-n", "--numcanaries"):
                num_canaries = arg
            elif opt in ("-a", "--attackers"):
                attackers = arg
            elif opt in ("-l", "--label"):
                label = label + arg + "_"

        if len(interface_list) < 2:
            print(
                "No CORE Bridges found, ensure the network_initializer executed correctly")
            exit()
        else:
            header = "CANARY REPORT: {} Bridges, {} Canaries, {} Nodes".format(
                bridges, int(num_canaries), (bridges * 5))

        # form random list of bridges with canaries based on canary parameter
        canaries = []
        for _ in range(int(num_canaries)):
            while(True):
                rnd = random.randint(1, bridges)
                if(rnd not in canaries):
                    canaries.append(rnd)
                    break

        # write canary trial log file header
        nodes = [i for i in range(bridges * 5)]
        header = header + "\nThreshold: {}".format(str(threshold))
        header = header + "\nNodes: {}".format(str(nodes))
        if(attackers):
            header = header + "\nAttackers: {}".format(str(attackers))
        if(canaries):
            header = header + "\nCanaries: {}".format(str(canaries))
        header = header + "\n\nBridge : Traffic : Time"
        _log.put(header)

        # for each bridge, pass its interface list to a canary process and kick
        # it off for the time_delta
        time_delta = 330
        bridge_id = 0
        for bridge in interface_list:
            if bridge:
                bridge_id += 1
                # deploy a canary on that bridge
                if(bridge_id in canaries):
                    p = multiprocessing.Process(target=CanaryShark.canary, args=(
                        bridge, _log, bridge_id, time_delta, float(threshold)))
                    processes.append(p)
                    print("Started Canary " + str(p.name) + " on " +
                          str(bridge_id) + ": " + str(bridge))
                    p.start()

        # let time_delta elapse before gathering _logs, allow child processes
        # to terminate, then dump the log
        CanaryShark.show_status(time_delta)
        name = "../reports/CANARY_LOG" + \
            str(label) + str(datetime.datetime.now())
        file = open(name, "w")
        print("Writing report...\r")
        while not _log.empty():
            file.write(_log.get())
        file.close()

        # finish each canary process
        for p in processes:
            p.join()
            print("Finished Canary " + str(p.name))


if __name__ == '__main__':
    CanaryShark.main(sys.argv[1:])
