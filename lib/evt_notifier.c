#include <stdlib.h>
#include <assert.h>
#include "evt_notifier.h"
#include "lib/resource.h"
#include "lib/timer.h"
#include "lib/socket.h"
#include "lib/event.h"


static pool *evt_notifier_pool;


static void evt_notifier_connect(struct evt_notifier *evt);
static void evt_connect_timeout(timer *t);
static void evt_notifier_connected(sock *s);
static void evt_notifier_tx(sock *sk);
static void evt_notifier_kick_tx(void *data);
static int evt_notifier_fire_tx(struct evt_notifier *evt);
static int evt_notifier_rx(struct birdsock *sk, uint size);
static void evt_notifier_connected_err(sock *sk, int status);
static void evt_close_and_connect_retry(struct evt_notifier *evt);
static void evt_timer_start(timer *t);
static void evt_notifier_err(sock *sk, int err);

struct evt_notifier *evt_notifier_new(const char *control_path) {
    struct evt_notifier *evt;

    evt_notifier_init();

    pool *p = rp_new(evt_notifier_pool, "evt_notifier");

    evt = mb_alloc(p, sizeof(*evt));
    bzero(evt, sizeof(*evt));

    evt->pool = p;

    evt->rx_buf = mb_alloc(evt->pool, 4096);
    evt->control_path = control_path;
    evt->event_tx = ev_new(p);
    evt->event_tx->hook = evt_notifier_kick_tx;
    evt->event_tx->data = evt;

    init_list(&evt->pending_data);

    evt->state = evt_state_not_ready;

    evt_notifier_connect(evt);
    return evt;
}


static void evt_timer_start(timer *t) {
#define connect_timeout 5
    btime time = connect_timeout S;
    btime randomize = random() % ((time / 4) + 1);
    tm_start(t, time - randomize);
}

static void evt_notifier_connect(struct evt_notifier *evt) {
    sock *s;

    s = sk_new(evt->pool);
    s->pool = evt->pool;
    s->type = SK_UNIX_ACTIVE;
    s->tx_hook = evt_notifier_connected;
    s->err_hook = evt_notifier_connected_err;
    s->rbsize = 1024;
    s->fast_rx = 1;
    s->data = evt;


    evt->sk = s;

    /* start timer */
    evt->connect_timer = tm_new_init(evt->pool, evt_connect_timeout, evt, 0, 0);
    evt_timer_start(evt->connect_timer);

    if (sk_open_active_unix(s, evt->control_path) < 0){
        log(L_WARN "sk_open_active_unix failed");
        return; /* reconnect next time on timeout */
    }
}

static void evt_connect_timeout(timer *t) {
    struct evt_notifier *evt;

    evt = t->data;

    evt_close_and_connect_retry(evt);
}

static void evt_close_and_connect_retry(struct evt_notifier *evt) {
    if (evt->sk) rfree(evt->sk);
    rfree(evt->connect_timer);
    evt->connect_timer = NULL;
    evt->sk = NULL;

    /**/
    evt_notifier_connect(evt);
}

static void evt_notifier_connected_err(sock *sk, int status) {
    struct evt_notifier *evt;
    evt = sk->data;

    log(L_WARN "Connection failed %s (%M)", evt->control_path, status);

    /* don't do anything, timer will expire and retry later */
}

static void
evt_notifier_connected(sock *s) {
    struct evt_notifier *evt;

    evt = s->data;

    tm_stop(evt->connect_timer);

    s->rx_hook = evt_notifier_rx; /*  */
    s->tx_hook = evt_notifier_tx;
    s->err_hook = evt_notifier_err;

    evt->rx_pos = evt->rx_buf;
    evt->rx_aux = NULL;

    evt->state = evt_state_ready;

    /* transmit data if any */
    if (!EMPTY_LIST(evt->pending_data) && !ev_active(evt->event_tx)) {
        ev_schedule(evt->event_tx);
    }
}

static void evt_notifier_err(sock *sk, int err) {
    struct evt_notifier *evt;
    evt = sk->data;

    evt->state = evt_state_not_ready;

    log(L_WARN "Connection with notifier lost (%M)", err);

    rfree(evt->sk);
    evt->sk = NULL;

    /* restart timer */
    evt_timer_start(evt->connect_timer);
}

void evt_notifier_close(struct evt_notifier *evt) {
    rfree(evt->pool);
}

static void evt_notifier_tx(sock *sk) {
    struct evt_notifier *evt;
    uint max;

    if (!sk) {
      return;
    }

    evt = sk->data;
    max = 128;
    while (--max && (evt_notifier_fire_tx(evt) >= 0));

    sk->tbuf = EMPTY_LIST(evt->pending_data) ? NULL : HEAD(evt->pending_data);

    if (evt->state != evt_state_not_ready && !max && sk->tbuf && !ev_active(evt->event_tx))
        ev_schedule(evt->event_tx);
}

void evt_notifier_schedule_packet(struct evt_notifier *evt, void *data, size_t len) {
    struct pending_data *p_data;

    p_data = mb_alloc(evt->pool, sizeof(struct pending_data) + len);
    bzero(p_data, sizeof(struct pending_data) + len);

    /* aïe marcel, memcpy :( */
    memcpy(p_data->data, data, len);
    p_data->len = len;

    add_tail(&evt->pending_data, &p_data->n);

    if (evt->state != evt_state_not_ready && !ev_active(evt->event_tx)) {
        ev_schedule(evt->event_tx);
    }
}

static void evt_notifier_kick_tx(void *data) {
    struct evt_notifier *evt;

    evt = data;
    (void) evt_notifier_tx(evt->sk);
}

static int evt_notifier_fire_tx(struct evt_notifier *evt) {
    struct pending_data *p_data;

    /* check if there is any data to send first */
    if (EMPTY_LIST(evt->pending_data)) {
        return -1;
    }

    p_data = HEAD(evt->pending_data);
    /* doubly make sure the list contains a valid node */
    if (!NODE_VALID(p_data)) {
        return -1;
    }

    evt->sk->tbuf = p_data->data;
    if (sk_send(evt->sk, p_data->len) <= 0)
        return -1;
    else rem_node(NODE p_data);

    mb_free(p_data);
    evt->sk->tbuf = NULL;
    return 0;
}

int evt_notifier_rx(struct birdsock *sk, uint size UNUSED) {
    struct evt_notifier *evt;
    evt = sk->data;

    byte *pkt_start = sk->rbuf;
    //byte *end = pkt_start + size;

    u8 type;
    u16 length;
    //byte *value;

    type = pkt_start[0];
    length = get_u16(&pkt_start[1]);
    // value = &pkt_start[2];

    switch (evt->state) {
        case evt_state_expect_keepalive:
            if (type == EVT_NOTIF_KA) {
                evt->state = evt_state_ready;
                assert(length == 0);
            } else {
                log(L_WARN "evt notifier in bad state\n");
            }
            break;
        default:
            log(L_WARN "evt notifier received unhandled bytes");
            break;
    }
    return 1;
}


void evt_notifier_init(void) {
    static int initiated = 0;
    if (initiated) return;
    evt_notifier_pool = rp_new(&root_pool, "evt_notifier");
    initiated = 1;
}
