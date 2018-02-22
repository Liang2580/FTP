#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: liang 
import configparser



config = configparser.ConfigParser()
config.read("accounts.cfg")

config["alex"]["username"]="liang"
print(config["alex"]["username"])