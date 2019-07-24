#pragma once

#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void printMac(const uint8_t* mac);
void printIp(ip_addr ip);
void printData(uint32_t size, const u_char* data);