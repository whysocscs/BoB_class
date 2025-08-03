#pragma once
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
uint8_t* make_my_mac(char* name);