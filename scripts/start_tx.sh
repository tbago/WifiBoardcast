#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one


#MY_TX=$TAOBAO
MY_TX=wlxe84e069cd324

MY_WIFI_CHANNEL=108 #5ghz channel
#MY_WIFI_CHANNEL=13 #2.4ghz channel

FEC_K=1

sh ./enable_monitor_mode.sh $MY_TX $MY_WIFI_CHANNEL

xterm -hold -e ./wfb_tx -u 5600 -r 60 -M 5 -B 20 -k $FEC_K $MY_TX &

gst-launch-1.0 -v videotestsrc ! video/x-raw,width=1280,height=720,framerate=30/1 ! videoscale ! videoconvert ! x264enc tune=zerolatency bitrate=10000 speed-preset=superfast ! rtph264pay ! udpsink host=127.0.0.1 port=5600
