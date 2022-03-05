# Assignment 2
Noah Woodin

## Description
a2.py takes a cap file as an argument and parses and analyzes it to gather information about the connections in the file.

This information gathered includes:
* Total number of connections
* Info about individual connections
* Total number of complete TCP connections
* Number of reset TCP connections
* Number of TCP connections that were still open when the trace capture ended
* Connection duration stats
* RTT stats
* Number of packets sent and received
* Window size stats

This program uses the following libraries:
   * struct - For unpacking the data in the cap file
   * statistics - For calculating the mean average
   * sys - For parsing the program arguments and exiting gracefully

## Program Executiona2
The program can be run from this directory using the following command, assuming your_cap_file is in the same directory:

`python3 a2.py <your_cap_file>`
