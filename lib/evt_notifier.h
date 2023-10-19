//
// Created by thomas on 7/12/23.
//

#ifndef BELBIRD_EVT_NOTIFIER_H
#define BELBIRD_EVT_NOTIFIER_H

#include "lib/lists.h"
#include "lib/event.h"
#include "lib/socket.h"
#include "lib/timer.h"

#define EVT_NOTIF_KA 1
#define EVT_NOTIF_CERT 2
#define EVT_NOTIF_LOCAL_CERT 3

enum evt_notifier_state {
    evt_state_not_ready,
    evt_state_ready,
    evt_state_expect_keepalive
};

struct pending_data {
    node n;
    size_t len;
    byte data[0];
};

struct evt_notifier {
    node n;				/* Node in list of all log hooks */
    pool *pool;
    sock *sk;				/* Private to sysdep layer */
    event *event_tx;
    byte *rx_buf, *rx_pos, *rx_aux;

    list pending_data;

    int state;
    const char *control_path;
    timer *connect_timer;
};


struct evt_notifier *evt_notifier_new(const char *control_path);

void evt_notifier_schedule_packet(struct evt_notifier *evt, void *data, size_t len);

void evt_notifier_close(struct evt_notifier *evt);

void evt_notifier_init(void);


#endif //BELBIRD_EVT_NOTIFIER_H
