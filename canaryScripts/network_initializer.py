"""
network_initializer
Description: The python script used to initialize a CORE network for the setup of a trial
Author: Winston Howard
Created Date: 10/30/19


Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import logging
import random
import datetime
import sys
import getopt
from core.emulator.coreemu import CoreEmu
from core.emulator.emudata import IpPrefixes
from core.emulator.enumerations import EventTypes
from core.emulator.enumerations import NodeTypes
from core.emulator.session import NodeOptions


class NetworkInitalizer:

    @classmethod
    def network_initializer(self, switches, composition, attackers):

        # check that switches is 2 <= s <= 10
        if(2 <= switches and switches <= 10):
            return "Error: Can only initalize a network of 2 to 10 switches in size"

        # ip generator
        prefixes = IpPrefixes(ip4_prefix="10.42.0.0/16")

        # create emulator instance for creating sessions and utility methods
        cli = False
        coreemu = globals().get("coreemu")

        # if not using the GUI provide path to the custom services directory
        if not coreemu:
            config = {"custom_services_dir": "../canaryServices"}
            coreemu = CoreEmu(config=config)
            cli = True
        session = coreemu.create_session()

        # create client node options
        node_options = NodeOptions()
        node_options.services = ["Node"]

        # create attacker node options
        attacker_options = NodeOptions()
        attacker_options.services = ["Attacker"]

        # must be in configuration state for nodes to start, when using
        # "add_node" below
        session.set_state(EventTypes.CONFIGURATION_STATE)
        node = []
        switch = []

        i = 0
        # create switches
        for _ in range(switches):
            y = random.randint(200, 700)
            x = random.randint(200, 700)
            switch.append(session.add_node(_type=NodeTypes.SWITCH))
            switch[i].setposition(x=x, y=y)
            i = i + 1

        # create list of randomly selected nodes for attacker deployment
        nodes = []
        if(attackers == "-1"):
            print("Generating attacker list...")
            for _ in range(switches * 5):
                while(True):
                    rnd = random.randint(0, switches * 5)
                    if(rnd not in nodes):
                        nodes.append(rnd)
                        break
            slc = (len(nodes) * composition)
            attackers = nodes[:int(slc)]
        else:
            nodes = [i for i in range(switches * 5)]
            if(attackers):
                attackers = attackers.split(',')
                attackers = [int(i) for i in attackers]
            else:
                attackers = []
        print("Nodes: " + str(nodes))
        print("Attackers: " + str(attackers))

        i = 0
        # create client nodes
        for _ in range(switches * 5):
            y = random.randint(150, 750)
            x = random.randint(150, 750)
            if(i in attackers):
                node.append(session.add_node(node_options=attacker_options))
            else:
                node.append(session.add_node(node_options=node_options))
            node[i].setposition(x=x, y=y)
            node_interface = prefixes.create_interface(node[i])

            # create interfaces to connect client nodes to switches
            if(i % switches == 0):
                switch_interface = prefixes.create_interface(switch[0])
                session.add_link(
                    node[i].id,
                    switch[0].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 1):
                switch_interface = prefixes.create_interface(switch[1])
                session.add_link(
                    node[i].id,
                    switch[1].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 2):
                switch_interface = prefixes.create_interface(switch[2])
                session.add_link(
                    node[i].id,
                    switch[2].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 3):
                switch_interface = prefixes.create_interface(switch[3])
                session.add_link(
                    node[i].id,
                    switch[3].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 4):
                switch_interface = prefixes.create_interface(switch[4])
                session.add_link(
                    node[i].id,
                    switch[4].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 5):
                switch_interface = prefixes.create_interface(switch[5])
                session.add_link(
                    node[i].id,
                    switch[5].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 6):
                switch_interface = prefixes.create_interface(switch[6])
                session.add_link(
                    node[i].id,
                    switch[6].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 7):
                switch_interface = prefixes.create_interface(switch[7])
                session.add_link(
                    node[i].id,
                    switch[7].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 8):
                switch_interface = prefixes.create_interface(switch[8])
                session.add_link(
                    node[i].id,
                    switch[8].id,
                    node_interface,
                    switch_interface)
            elif(i % switches == 9):
                switch_interface = prefixes.create_interface(switch[9])
                session.add_link(
                    node[i].id,
                    switch[9].id,
                    node_interface,
                    switch_interface)
            i = i + 1

        # create interfaces to connect switches
        if(switches >= 2):
            switch_a = prefixes.create_interface(switch[0])
            switch_b = prefixes.create_interface(switch[1])
            session.add_link(switch[0].id, switch[1].id, switch_a, switch_b)
        if(switches >= 3):
            switch_a = prefixes.create_interface(switch[1])
            switch_b = prefixes.create_interface(switch[2])
            session.add_link(switch[1].id, switch[2].id, switch_a, switch_b)
        if(switches >= 4):
            switch_a = prefixes.create_interface(switch[2])
            switch_b = prefixes.create_interface(switch[3])
            session.add_link(switch[2].id, switch[3].id, switch_a, switch_b)
        if(switches >= 5):
            switch_a = prefixes.create_interface(switch[3])
            switch_b = prefixes.create_interface(switch[4])
            session.add_link(switch[3].id, switch[4].id, switch_a, switch_b)
        if(switches >= 6):
            switch_a = prefixes.create_interface(switch[4])
            switch_b = prefixes.create_interface(switch[5])
            session.add_link(switch[4].id, switch[5].id, switch_a, switch_b)
        if(switches >= 7):
            switch_a = prefixes.create_interface(switch[5])
            switch_b = prefixes.create_interface(switch[6])
            session.add_link(switch[5].id, switch[6].id, switch_a, switch_b)
        if(switches >= 8):
            switch_a = prefixes.create_interface(switch[6])
            switch_b = prefixes.create_interface(switch[7])
            session.add_link(switch[6].id, switch[7].id, switch_a, switch_b)
        if(switches >= 9):
            switch_a = prefixes.create_interface(switch[7])
            switch_b = prefixes.create_interface(switch[8])
            session.add_link(switch[7].id, switch[8].id, switch_a, switch_b)
        if(switches >= 10):
            switch_a = prefixes.create_interface(switch[8])
            switch_b = prefixes.create_interface(switch[9])
            session.add_link(switch[8].id, switch[9].id, switch_a, switch_b)

        # instantiate session
        session.instantiate()
        print("Session Instantiated, CLI = " + str(cli))

        # if the cli is being used terminate the session after 360 (canaries
        # terminate after 340 + 20 seccond initalization delay) seconds
        if(cli):
            stop_time = datetime.datetime.now() + datetime.timedelta(0, 360)
            while datetime.datetime.now() < stop_time:
                pass
            coreemu.delete_session(session.id)
            print("Session Terminated by Timer")


def main(argv):
    """
    The main function that checks for optional command line options
    """
    switches = random.randint(2, 10)
    comp = random.random()
    args = []
    attackers = -1
    try:
        opts, args = getopt.getopt(
            argv, "hs:c:a:", [
                "switches=", "composition=", "attackers="])
    except getopt.GetoptError:
        print ('Error: expected network_initializer.py -s <number of switches> -c <attacker composition> -a <list of attackers>')
        if(args):
            print(args)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print (
                'network_initializer.py -s <number of switches> -c <attacker composition> -a <list of attackers>')
            sys.exit()
        elif opt in ("-s", "--switches"):
            switches = arg
        elif opt in ("-c", "--composition"):
            comp = arg
        elif opt in ("-a", "--attackers"):
            attackers = arg
    NetworkInitalizer.network_initializer(
        int(switches), float(comp), str(attackers))


if __name__ in {"__main__", "__builtin__"}:
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])
