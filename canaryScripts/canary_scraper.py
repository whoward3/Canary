"""
canary_scraper
Description: Simple Python functions for scraping data from canary log files for analysis
Author: Winston Howard
Created Date: 02/23/20

 
Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import os
import re
import statistics
import matplotlib.pyplot as plt
from matplotlib.colors import hsv_to_rgb
import numpy as np
from sklearn.linear_model import LinearRegression

class ReportScraper():
 """
 Functions to be used to generate a summary for a report
 """
 @classmethod
 def report_summarizer(self,path):
    """
    The function used for scraping log files of a given path
    """
    directory = os.listdir(path)
    directory = sorted(directory)
    global_entropys = []
    global_packets = []
    global_detections = []
    global_detection_fails = 0
    i = 0
    for file in directory:

        try:
         # Open the file for reading,
         f = open(path+file, "r")
         report = f.read()

         # Compute Trial Packet Data
         packet_list = ReportScraper.get_packets(report)
         packet_report = ""
         for canary in packet_list:
             packet_report = packet_report + "Canary {} Observed Packets: {}\n".format(canary,packet_list[canary])
             global_packets.append(int(packet_list[canary]))

         # Compute Detection Data
         # Scrape all packets and violations from the trial log file in order
         # [0-9]*:(?= Destination)      -> Each Observed Packet
         # ~[0-9]*                      -> Each Reported Threshold Violation (DDoS Detection)
         entries = re.findall("[0-9]*:(?= Destination)|~[0-9]*", report)
         detect_time = -999
         p = 0
         # Iterate through all events in a report (packets and detections)
         for e in entries:
             #If an entry is a ddos detection report how many packets were observed prior
             if("~" in e):
                 detect_time = p
                 break
             p+=1

         # Update Global Detection List
         if(detect_time == -999):
             global_detection_fails += 1
             detect_time = "N/A"
         else:
             global_detections.append(detect_time)
             detect_time = str(detect_time) + " Packets"

         # Compute Trial Entropy Data    
         res = re.findall("(?<=@.{3}Bridge Entropy: ).*", report)
         res = [float(i) for i in res]
         global_entropys = global_entropys + res
         ma = round(max(res),4)
         mi = round(min(res),4)
         me = round(statistics.mean(res),4)
         entropy_report = "Trial {}; Max E: {}, Min E: {}, Mean E: {}, First Detection: {}\n".format(file[11:], ma, mi, me,detect_time)               
            
         # Report findings 
         print(entropy_report+packet_report,end="\n")

         # Print entropy by attacker %
         for e in res:
          c = file[17] + file[18] + file[19]
          c = str(int(float(c)*100)) + '%'
          #print("{}\t{}".format(c, str(e)))


         f.close()
         i += 1
        except Exception as a:
         print(a,end = "\n")    

    gma = round(max(global_entropys),4)
    gmi = round(min(global_entropys),4)
    gme = round(statistics.mean(global_entropys),4)
    gstd = round(statistics.stdev(global_entropys),4)

    gpma = round(max(global_packets),4)
    gpmi = round(min(global_packets),4)
    gpme = round(statistics.mean(global_packets),4)
    gpstd = round(statistics.stdev(global_packets),4)
    
    if(global_detections):
     gdme = round(statistics.mean(global_detections),4)
     global_detection_succeses = len(global_detections)
     successrate = int(global_detection_succeses/(global_detection_succeses+global_detection_fails)*100)
    else:
     gdme = "N/A"
     successrate = 0

    print("\nGlobal Entropy Report; Max E: {}, Min E: {}, Mean E: {}, Standard Deviation E: {}, Threshold E: {}\n".format(gma, gmi, gme,gstd,(gme)*.90))
    print("Global Packet; Max P: {}, Min P: {}, Mean P: {}, Standard Deviation P: {}\n".format(gpma, gpmi, gpme,gpstd))
    print("Global Simulation Report; Detection Rate: {}%, Mean Detection Packets: {}\n".format(successrate,gdme))

 @classmethod
 def get_packets(self,report):
    """
    The function used for computing the number of packets seen per canary
    """
    res = re.findall("[0-9]*(?=: Destination)",report)
    packet_dict = {}
    for p in res:
     if p:
      if not p in packet_dict:
       packet_dict[p] = 1
      else:
       packet_dict[p] += 1
    return packet_dict

class ReportGrapher():
 """
 Functions to be used to generate a graph for a report
 """
 @classmethod
 def report_grapher(self,path):
    """
    The function used for producing a graph of an Experiment
    """
    my_colors = [hsv_to_rgb([(i * 0.618033988749895) % 1.0, 1, 1]) for i in range(1000)]
    subdirectories = os.listdir(path)
    subdirectories = sorted(subdirectories)
    i = 0
    plt.grid(b=True,which="both",axis="both")
    for subdirectory in subdirectories:
     print("Plotting {}".format(subdirectory))
     try:
         res = ReportGrapher.get_detections(path+subdirectory+"/")    
         xpts = np.asarray(res[0])
         ypts = np.asarray(res[1])
         vpt = res[2]
         z = np.polyfit(xpts, ypts, deg=1)
         p = np.poly1d(z)

         color = my_colors[i]
         plt.plot(xpts, p(xpts), label=subdirectory,color=color,alpha=0.2)
         if(vpt != -1): plt.axvline(x=vpt, color=color)
         i+=1
     except Exception as ex:
         print(ex)     

    plt.title("Detection Count by Trial Progress")
    plt.ylabel('Detections')
    plt.xlabel('Simulation Period [(Pi/Pt)*100]')
    plt.legend(loc='upper right')
    plt.show()
 
 @classmethod
 def get_reports(self,path):
    """
    The helper function used by the grapher to parse a series of reports
    """
    directories = os.listdir(path)
    xpts = [0]
    ypts = [0]
    vpts = []
    for file in directories:

        try:
         # Open the file for reading,
         f = open(path+file, "r")
         report = f.read()

         # Compute summary of all trials in the experiment
         entries = re.findall("(?<=@.{3}Bridge Entropy: ).*|[0-9]*:(?= Destination)|~[0-9]*", report)
         violations = re.findall("~[0-9]*",report)
         i = 0
         xs = []
         ys = []
         first = False
         for e in entries:
             if("~" in e and first == False):                 
                 vpts.append((i/(len(entries)-len(violations)))*100)
                 first = True
             elif(":" not in e and "~" not in e):
                 ys.append(e)
                 xs.append((i/(len(entries)-len(violations)))*100)
             i+=1
         ys = [float(i) for i in ys]
         xpts = xpts + xs
         ypts = ypts + ys        

         # Break Here if attempting to only parse a single trial to represent the Experiment

        except Exception as a:
         print(a,end = "\n")

    # Return xPts, Ypts, and Mean first flag for this Exp
    try:        
     v = statistics.mean(vpts)
    except Exception:
     v = -1
    return [xpts,ypts,v]

 @classmethod
 def get_detections(self,path):
    """
    The helper function used by the grapher to parse a report for all its detections by report progress
    """
    directory = os.listdir(path)
    xpts = [0]
    ypts = [0]
    for file in directory:

        try:
         # Open the file for reading,
         f = open(path+file, "r")
         report = f.read()

         # Scrape all packets and violations from the trial log file in order
         # [0-9]*:(?= Destination)      -> Each Observed Packet
         # ~[0-9]*                      -> Each Threshold Violation/DDoS Detection
         entries = re.findall("[0-9]*:(?= Destination)|~[0-9]*", report)
         detections = re.findall("~[0-9]*",report)
         i = 0
         detections_count = 0
         xs = []
         ys = []

         #Iterate through all events in a report (packets and detections)
         for e in entries:
             #If an entry is a ddos detection, add the number of detections so far to the y axis and the progress of the trial to the x axis
             if("~" in e):                 
                 detections_count += 1
                 ys.append(detections_count)
                 xs.append((i/(len(entries)-len(detections)))*100)
             i+=1
         xpts = xpts + xs
         ypts = ypts + ys        

        except Exception as a:
         print(a,end = "\n")

    # Return xPts, Ypts
    return [xpts,ypts,-1]

p = input("Experiment Path: ")
print(p+"\n\n")
ReportScraper.report_summarizer(p)