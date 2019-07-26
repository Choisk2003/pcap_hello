#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include "protocol/all.h"

const char *HTTP_METHOD_HTTP = "HTTP ";
const char *HTTP_METHOD_GET = "GET ";
const char *HTTP_METHOD_POST = "POST ";
const char *HTTP_METHOD_PUT = "PUT ";
const char *HTTP_METHOD_DELETE = "DELETE ";
const char *HTTP_METHOD_CONNECT = "CONNECT ";
const char *HTTP_METHOD_OPTIONS = "OPTIONS ";
const char *HTTP_METHOD_TRACE = "TRACE ";
const char *HTTP_METHOD_PATCH = "PATCH ";

const char *HTTP_METHOD[9] =
    {
        HTTP_METHOD_HTTP,
        HTTP_METHOD_GET,
        HTTP_METHOD_POST,
        HTTP_METHOD_PUT,
        HTTP_METHOD_DELETE,
        HTTP_METHOD_CONNECT,
        HTTP_METHOD_OPTIONS,
        HTTP_METHOD_TRACE,
        HTTP_METHOD_PATCH};

bool checkHttp(const u_char *data)
{
    int i = 0, j = 0, chk = 1;
    char check[7];
    for (i; i < 9; i++)
    {
        for (j = 0; HTTP_METHOD[i][j] != ' '; j++)
        {
            check[j] = data[j];
        }
        chk = (strncmp((const char *)check, (const char *)HTTP_METHOD[i], j));
        if (chk == 0)
        {
            printf("HTTP\n");
            printf("HTTP METHOD: %s\n", (char *)HTTP_METHOD[i]);
            return true;
        }
    }
    return false;
}