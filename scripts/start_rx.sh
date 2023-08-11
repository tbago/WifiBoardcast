#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one


MY_RX=wlp6s0

MY_WIFI_CHANNEL=108 #5ghz channel
#MY_WIFI_CHANNEL=13 #2.4ghz channel


sh ./enable_monitor_mode.sh $MY_RX $MY_WIFI_CHANNEL

./wfb_rx -u 5610 -r 60 $MY_RX 

