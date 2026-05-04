#!/bin/bash

sudo ip -4 rule delete table 51820
sudo ip -4 rule delete table main suppress_prefixlength 0
sudo ip -6 rule delete table 51820
sudo ip -6 rule delete table main suppress_prefixlength 0
sudo ip link delete dev wgo1

