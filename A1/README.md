# Assignment 1
Noah Woodin

## Description
SmartClient.py takes a uri as an argument and attempts to connect to the site and extract information about the site.

This information includes:
* Whether the site supports http2
* Recording cookies on the site
* If the site is password protected

This program uses the following libraries:
   * socket - For creating sockets and sending and receiving data
   * ssl - For wrapping the sockets in order to use https
   * re - For parsing the http/https responses
   * sys - For parsing the program arguments and exiting gracefully

## Program Execution
The program can be run from this directory using the following command:

`python3 SmartClient.py <your_uri>`
