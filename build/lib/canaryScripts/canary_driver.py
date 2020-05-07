"""
canary_driver
Description: A quick and dirty driver script to automate the deployment of Project Canary trials. The driver script can complete a canary trial every 370 seconds.
Author: Winston Howard
Created Date: 02/17/20


Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import subprocess
import time
import random
import re
import sys
import getopt


class CanaryDriver():

    @classmethod
    def start(self, trials):
        """
        Start experimentation for n trials
        """
        try:
            # start core process, dumps an warning if the core-daemon is
            # already running
            print("DRIVER: Starting Core Daemon...")
            core_daemon = subprocess.Popen(args=["sudo", "core-daemon"])

            # essential params for the network_initializer
            s = 1  # -s <number of switches>
            c = -0.25  # -c <attacker composition>

            # essential params for the canary_shark
            t = 3.5  # -t <entropy threshold>
            n = 1  # -n <number of canaries>

            # non-essential params for canary logging
            a = []  # -a <list of attackers>
            l = ""  # -l <report label>

            # initalize canary composition local variable for changes in canary
            # deployment
            n_temp = 0

            for i in range(trials):

                # drive simulations across 3 different topologies
                if(i < trials / 3):
                    s = 3
                    t = 3.0111
                elif(i < (trials / 3 * 2)):
                    s = 6
                    t = 3.4200
                else:
                    s = 9
                    t = 3.3790

                # every n trials change composition by 25% including 0 and 100
                if(i % 15 == 0):
                    c = round(((c + 0.25) % 1.25), 2)

                    # after the completion of a composition loop reduce the
                    # number of canaries
                    if(c == 0 and n_temp <= s):
                        n = s - n_temp
                        n_temp += 1
                    elif(n_temp > s):
                        n = s
                        n_temp = 0

                l = "s-{}_c-{}_n-{}".format(s, c, n)

                # generate attacker list
                nodes = []
                for _ in range(s * 5):
                    while(True):
                        rnd = random.randint(0, s * 5)
                        if(rnd not in nodes):
                            nodes.append(rnd)
                            break
                slc = (len(nodes) * c)
                a = nodes[:int(slc)]

                # convert a to a string without the [] for passing
                a = str(a).replace('[', '').replace(']', '').replace(" ", '')

                print("\nDRIVER: Starting trial {}/{}/{}".format(i + 1, trials, l))

                # ensure the network is empty
                status = CanaryDriver.get_bridges()
                if(status != "Error: No CORE Bridges found, ensure the network_initializer executed correctly"):
                    print("DRIVER ERROR: Old session data remains")
                    print(status)
                    quit()

                # initalize a trial network
                print(
                    "DRIVER: No residual bridges found, initalizing a trial network...")
                initalizer_daemon = subprocess.Popen(
                    args=[
                        "sudo",
                        "python3",
                        "network_initializer.py",
                        "-s",
                        str(s),
                        "-c",
                        str(c),
                        "-a",
                        str(a)])
                time.sleep(20)

                # ensure the network is populated
                status = CanaryDriver.get_bridges()
                if(status == "Error: No CORE Bridges found, ensure the network_initializer executed correctly"):
                    print("DRIVER ERROR: " + status)
                    quit()
                print(
                    "DRIVER: Initalization Successful! Trial {}/{}/{} network configuration: ".format(
                        i +
                        1,
                        trials,
                        l))
                print(status)

                # initalize the canaries
                print("DRIVER: Starting Canary Shark...")
                canary_daemon = subprocess.Popen(
                    ["python3", "canary_shark.py", "-t", str(t), "-n", str(n), "-a", str(a), "-l", str(l)])

                # allow the trial to safely complete
                time.sleep(340)
                print(
                    "DRIVER: Trial {}/{}/{} complete! Begining cleanup...".format(i + 1, trials, l))
                try:
                    canary_daemon.wait(timeout=60)
                    print("DRIVER: Canary Initalizer Terminated")
                    initalizer_daemon.wait(timeout=60)
                    print("DRIVER: Network Initalizer Terminated")
                except Exception as e:
                    print("DRIVER: KILL EXCEPTION: " + str(e))
                subprocess.run(args=["sudo", "core-cleanup"])
                time.sleep(10)
                print("DRIVER: Trial {} Done\n\n\n".format(i + 1))

        except Exception as a:
            print("DRIVER: EXCEPTION: " + str(a))
        print("DRIVER: Experimentation Complete!")
        core_daemon.kill()

    @classmethod
    def get_bridges(self):
        """
        Gather the interfaces for each bridge, return error if we were unable to find interfaces/bridges else return the output of brctl show
        """
        # check=true is key to ensure python raises an exception here instead
        # of piping bad data to our canaries
        bridge_call = subprocess.run(
            ["brctl", "show"], stdout=subprocess.PIPE, text=True, check=True)
        split_list = list(re.split('\n|\t', bridge_call.stdout))
        interface_list = []
        bridge_list = []
        for item in split_list:
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

        if len(interface_list) < 2:
            return "Error: No CORE Bridges found, ensure the network_initializer executed correctly"
        else:
            return bridge_call.stdout


def main(argv):
    """
    The main function that checks for optional command line options
    """
    trials = 450
    args = []
    try:
        opts, args = getopt.getopt(argv, "ht:", ["trials="])
    except getopt.GetoptError:
        print('Error: expected canary_driver.py -t <number of trials>')
        if(args):
            print(args)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('canary_driver.py -t <number of trials>')
            sys.exit()
        elif opt in ("-t", "--trials"):
            trials = arg
    CanaryDriver.start(int(trials))


if __name__ == "__main__":
    main(sys.argv[1:])
