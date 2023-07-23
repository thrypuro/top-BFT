//
// Created by thrypuro on 22/07/23.
//

#include "Leader_enc.h"
#include <sgx_tcrypto.h>
#include "sgx_trts.h"
#include <stdio.h>
#include <stdarg.h>

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
}
void printf_helloworld1()
{
    printf("Hello World\n");
}