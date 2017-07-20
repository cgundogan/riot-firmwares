#ifndef COAP_LED_H
#define COAP_LED_H

#include <inttypes.h>

#include "nanocoap.h"

#ifdef __cplusplus
extern "C" {
#endif

ssize_t led_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len);

void init_btn_thread(void);

#ifdef __cplusplus
}
#endif

#endif
