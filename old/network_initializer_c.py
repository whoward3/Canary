"""
network_initializer_c
Description: The python script used to initalize a core network for the setup of a (c)lean trial without any attackers in the network
Author: Winston Howard
Created Date: 10/30/19

Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

from core.emulator.coreemu import CoreEmu
from core.emulator.emudata import IpPrefixes
from core.emulator.enumerations import EventTypes
from core.emulator.enumerations import NodeTypes
from core.emulator.session import NodeOptions
from myServices import *
import logging
import random
import time
import datetime

def main():

 # ip generator
 prefixes = IpPrefixes(ip4_prefix="10.42.0.0/16")

 # create emulator instance for creating sessions and utility methods
 cli = False 
 coreemu = globals().get("coreemu")
 if not coreemu:
    config = {"custom_services_dir": "/home/whoward3/coreScripts/myServices"}
    coreemu = CoreEmu(config=config)
    cli = True
 session = coreemu.create_session()

 # create client node options
 nodeOptions = NodeOptions()
 nodeOptions.services = ["Node"]

 # create attacker node options
 attackerOptions = NodeOptions()
 attackerOptions.services = ["Attacker"]
 
 # must be in configuration state for nodes to start, when using "add_node" below
 session.set_state(EventTypes.CONFIGURATION_STATE)
 switches = 5 #random.randint(2,10)
 node = []
 switch = []
 
 i = 0
 # create switches
 for _ in range(switches):
    y = random.randint(200,700)
    x = random.randint(200,700)
    switch.append(session.add_node(_type=NodeTypes.SWITCH))
    switch[i].setposition(x=x,y=y)
    i=i+1

 i = 0
 # create client nodes
 for _ in range(switches*5):
    y = random.randint(150,750)
    x = random.randint(150,750)
    if(i % 3 == 0 and i < (switches*5)):
      node.append(session.add_node(node_options=nodeOptions))
    else:
      node.append(session.add_node(node_options=nodeOptions)) 
    node[i].setposition(x=x,y=y)
    nodeInterface = prefixes.create_interface(node[i])

    # create interfaces to connect client nodes to switches
    if(i%switches==0):
     routerInterface = prefixes.create_interface(switch[0])
     session.add_link(node[i].id, switch[0].id, nodeInterface, routerInterface)
    elif(i%switches==1):
     routerInterface = prefixes.create_interface(switch[1])
     session.add_link(node[i].id, switch[1].id, nodeInterface, routerInterface)
    elif(i%switches==2):
     routerInterface = prefixes.create_interface(switch[2])
     session.add_link(node[i].id, switch[2].id, nodeInterface, routerInterface)
    elif(i%switches==3):
     routerInterface = prefixes.create_interface(switch[3])
     session.add_link(node[i].id, switch[3].id, nodeInterface, routerInterface)
    elif(i%switches==4):
     routerInterface = prefixes.create_interface(switch[4])
     session.add_link(node[i].id, switch[4].id, nodeInterface, routerInterface)
    elif(i%switches==5):
     routerInterface = prefixes.create_interface(switch[5])
     session.add_link(node[i].id, switch[5].id, nodeInterface, routerInterface)
    elif(i%switches==6):
     routerInterface = prefixes.create_interface(switch[6])
     session.add_link(node[i].id, switch[6].id, nodeInterface, routerInterface)
    elif(i%switches==7):
     routerInterface = prefixes.create_interface(switch[7])
     session.add_link(node[i].id, switch[7].id, nodeInterface, routerInterface)
    elif(i%switches==8):
     routerInterface = prefixes.create_interface(switch[8])
     session.add_link(node[i].id, switch[8].id, nodeInterface, routerInterface)
    elif(i%switches==9):
     routerInterface = prefixes.create_interface(switch[9])
     session.add_link(node[i].id, switch[9].id, nodeInterface, routerInterface)
    i=i+1

 # create interfaces to connect switches
 if(switches >= 2):
  switchA = prefixes.create_interface(switch[0])
  switchB = prefixes.create_interface(switch[1])
  session.add_link(switch[0].id,switch[1].id,switchA,switchB)
 if(switches >= 3):
  switchA = prefixes.create_interface(switch[1])
  switchB = prefixes.create_interface(switch[2])
  session.add_link(switch[1].id,switch[2].id,switchA,switchB)
 if(switches >= 4):
  switchA = prefixes.create_interface(switch[2])
  switchB = prefixes.create_interface(switch[3])
  session.add_link(switch[2].id,switch[3].id,switchA,switchB)
 if(switches >= 5):
  switchA = prefixes.create_interface(switch[3])
  switchB = prefixes.create_interface(switch[4])
  session.add_link(switch[3].id,switch[4].id,switchA,switchB)
 if(switches >= 6):
  switchA = prefixes.create_interface(switch[4])
  switchB = prefixes.create_interface(switch[5])
  session.add_link(switch[4].id,switch[5].id,switchA,switchB)
 if(switches >= 7):
  switchA = prefixes.create_interface(switch[5])
  switchB = prefixes.create_interface(switch[6])
  session.add_link(switch[5].id,switch[6].id,switchA,switchB)
 if(switches >= 8):
  switchA = prefixes.create_interface(switch[6])
  switchB = prefixes.create_interface(switch[7])
  session.add_link(switch[6].id,switch[7].id,switchA,switchB)
 if(switches >= 9):
  switchA = prefixes.create_interface(switch[7])
  switchB = prefixes.create_interface(switch[8])
  session.add_link(switch[7].id,switch[8].id,switchA,switchB)
 if(switches >= 10):
  switchA = prefixes.create_interface(switch[8])
  switchB = prefixes.create_interface(switch[9])
  session.add_link(switch[8].id,switch[9].id,switchA,switchB)

 # instantiate session
 session.instantiate()

 print("Session Instantiated, CLI = "+str(cli))

 # if the cli is being used terminate the session after 360 (canaries terminate after 340 + 20 seccond initalization delay) secconds 
 if(cli):
    stop_time = datetime.datetime.now() + datetime.timedelta(0,360)
    while datetime.datetime.now() < stop_time:
       pass
    coreemu.delete_session(session.id)
    print("Session Terminated by Timer")

if __name__ in {"__main__", "__builtin__"}:
    logging.basicConfig(level=logging.INFO)
    main()