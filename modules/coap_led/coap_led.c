#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "board.h"
#include "periph/gpio.h"

#include "fmt.h"

#include "nanocoap.h"
#include "net/gcoap.h"

#include "coap_utils.h"
#include "coap_common.h"
#include "coap_led.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#define BTN_QUEUE_SIZE    (8)
#define BTN_CB_MSG_TYPE   (0x666)
static msg_t _btn_msg_queue[BTN_QUEUE_SIZE];
static char btn_stack[THREAD_STACKSIZE_DEFAULT];
kernel_pid_t btn_pid = KERNEL_PID_UNDEF;

ssize_t led_handler(coap_pkt_t* pdu, uint8_t *buf, size_t len)
{
    ssize_t p = 0;
    char rsp[16];
    unsigned code = COAP_CODE_EMPTY;

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pdu));

    switch(method_flag) {
    case COAP_GET:
    {
        p += sprintf(rsp, "%i", gpio_read(LED0_PIN) == 0);
        DEBUG("[DEBUG] Returning LED value '%s'\n", rsp);
        code = COAP_CODE_205;
        break;
    }
    case COAP_PUT:
    case COAP_POST:
    {
        /* convert the payload to an integer and update the internal value */
        char payload[16] = { 0 };
        memcpy(payload, (char*)pdu->payload, pdu->payload_len);
        uint8_t val = strtol(payload, NULL, 10);
        if ( (pdu->payload_len == 1) &&
             ((val == 1) || (val == 0))) {
            /* update LED value */
            DEBUG("[DEBUG] Update LED value '%i'\n", val);
            gpio_write(LED0_PIN, val);
            code = COAP_CODE_CHANGED;
            p += sprintf(rsp, "led:%i", val);
        }
        else {
            DEBUG("[ERROR] Wrong LED value given '%i'\n", val);
            code = COAP_CODE_BAD_REQUEST;
        }
        break;
    }
    default:
        DEBUG("[Error] Bad request\n");
        code = COAP_CODE_BAD_REQUEST;
        break;
    }

    return coap_reply_simple(pdu, code, buf, len, COAP_FORMAT_TEXT, (uint8_t*)rsp, p);
}

static void cb(void *arg)
{
    puts("gpio_int_cb");
    msg_t msg;
    msg.type = BTN_CB_MSG_TYPE;
    msg_send(&msg, btn_pid);
}

void *btn_thread(void *args)
{
    msg_init_queue(_btn_msg_queue, BTN_QUEUE_SIZE);
    msg_t msg;

    while(1){
        msg_receive(&msg);
        if (msg.type == BTN_CB_MSG_TYPE){

            puts("btn_thread received message of type BTN_CB_MSG_TYPE");

            int toggle=0;
            uint8_t snd_led[64] = { 0 };

            if(!gpio_read(LED0_PIN)){
                toggle=1;
                gpio_set(LED0_PIN);
            }
            else{
                toggle=0;
                gpio_clear(LED0_PIN);
            }

            size_t p = 0;
            p += sprintf((char*)&snd_led[p], "led:%i", toggle);
            snd_led[p] = '\0';
            for(int retrans=0;retrans<4;retrans++){
                send_coap_post((uint8_t*)"/server", snd_led);
                xtimer_usleep(200);
            }
        }
        else{
            puts("btn_thread received message of UNKNOWN type");
        }
    }


    return NULL;
}


void init_btn_thread(void)
{
    /* Initialize the TSL2561 sensor */
    printf("+------------Initializing button thread ------------+\n");

    gpio_init_int(BTN0_PIN, GPIO_IN_PU, GPIO_FALLING, cb, NULL);

    /* create the sensors thread that will send periodic updates to
       the server */
    btn_pid = thread_create(btn_stack, sizeof(btn_stack),
                                    THREAD_PRIORITY_MAIN - 1,
                                    THREAD_CREATE_STACKTEST, btn_thread,
                                    NULL, "btn thread");
    if (btn_pid == -EINVAL || btn_pid == -EOVERFLOW) {
        puts("Error: failed to create btn thread, exiting\n");
    }
    else {
        puts("Successfuly created btn thread !\n");
    }
}