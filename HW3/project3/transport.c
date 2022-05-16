/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

// Added
#include <arpa/inet.h>
#include <stdbool.h>

// Added
#define WINDOW 3072

enum {
    // Connection Estabilished
    CSTATE_ESTABLISHED,
    // Connection Start
    CSTATE_LISTEN,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RCVD,
    // Connection Close
    CSTATE_CLOSED,
    // Active
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    // Passive
    CSTATE_CLOSE_WAIT,
    CSTATE_LAST_ACK
};    /* obviously you should have more states */

typedef enum {
    SYN,
    SYNACK,
    ACK,
    DATA,
    FIN,
    FINACK
} SegmentType;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
    tcp_seq prev_seq;
    tcp_seq prev_ack;
    size_t prev_len;
    // receiver
    tcp_seq rcvd_seq;
    tcp_seq rcvd_ack;
    size_t rcvd_len;
    // sender
    tcp_seq next_seq;
    // window
    uint32_t remainder_window;
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

// Added
STCPHeader *CreateSegment(tcp_seq seq_no, tcp_seq ack_no, SegmentType type, char *data, size_t length);
bool SendSegment(mysocket_t sd, context_t *ctx, SegmentType type, char *data, size_t data_len);
bool WaitSegment(mysocket_t sd, context_t *ctx, SegmentType type);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    bool success;

    ctx = (context_t *) malloc(sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    // Initialize ctx of remainder_window, connection state
    ctx->remainder_window = WINDOW;
    ctx->connection_state = CSTATE_LISTEN;

    // 3-way handshake: Active side
    if (is_active) {
        // Current state: LISTEN, sending a SYN
        success = SendSegment(sd, ctx, SYN, NULL, 0);
        if(success == false) {
            fprintf(stderr, "3-way handshake: sending a SYN error\n");
            free(ctx);
            assert(0);
        }

        // Current state: SYN_SENT, waiting for a SYNACK
        ctx->connection_state = CSTATE_SYN_SENT;
        success = WaitSegment(sd, ctx, SYNACK);
        if(success == false) {
            fprintf(stderr, "3-way handshake: waiting a SYNACK error\n");
            free(ctx);
            assert(0);
        }

        // Current state: ESTABLISHED, sending an ACK
        ctx->connection_state = CSTATE_ESTABLISHED;
        success = SendSegment(sd, ctx, ACK, NULL, 0);
        if(success == false) {
            fprintf(stderr, "3-way handshake: sending an ACK error\n");
            free(ctx);
            assert(0);
        }
    }
    // 3-way handshake: Passive side
    else {
        // Current state: LISTEN, waiting for a SYN
        success = WaitSegment(sd, ctx, SYN);
        if(success == false) {
            fprintf(stderr, "3-way handshake: waiting a SYN error\n");
            free(ctx);
            assert(0);
        }

        // Current state: SYN_RCVD, sending a SYNACK,
        // and then, waiting for an ACK
        ctx->connection_state = CSTATE_SYN_RCVD;
        success = SendSegment(sd, ctx, SYNACK, NULL, 0);
        if(success == false) {
            fprintf(stderr, "3-way handshake: sending an SYNACK error\n");
            free(ctx);
            assert(0);
        }
        success = WaitSegment(sd, ctx, ACK);
        if(success == false) {
            fprintf(stderr, "3-way handshake: waiting an ACK error\n");
            free(ctx);
            assert(0);
        }

        // Current state: SYN_RCVD
        ctx->connection_state = CSTATE_ESTABLISHED;
    }

    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    char *buffer;
    size_t max_len = 0;
    size_t data_len = 0;
    bool success = true;

    // Allocate memory to the buffer
    buffer = (char *) malloc(STCP_MSS + sizeof(STCPHeader));
    if(buffer == NULL) {
        fprintf(stderr, "In control_loop: malloc failed!\n");
        assert(0);
    }

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        // max_len: smaller one between remainder_window and STCP_MSS
        max_len = (STCP_MSS < ctx->remainder_window) ? STCP_MSS : ctx->remainder_window;

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            if((int)max_len <= 0) {
                while(ctx->remainder_window < WINDOW) {
                    // Wait for an ACK
                    success = WaitSegment(sd, ctx, ACK);
                    if(success == false) {
                        fprintf(stderr, "In control_loop: Waiting an ACK error\n");
                        free(buffer);
                        return;
                    }
                    //printf("remain_window = %d\n", ctx->remainder_window);
                }
                continue;
            }
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            data_len = stcp_app_recv(sd, buffer, max_len);
            if(data_len == 0) {
                fprintf(stderr, "In control_loop: No Data from stcp_app_recv()\n");
                free(buffer);
                return;
            }

            // Send App data
            success = SendSegment(sd, ctx, DATA, buffer, data_len);
            if(success == false) {
                fprintf(stderr, "In control_loop: Sending App Data error\n");
                free(buffer);
                return;
            }

            // Update next_seq no.
            ctx->next_seq = ctx->prev_seq + data_len;

            //printf("After send: remain_window = %d\n", ctx->remainder_window);

            // Wait for an ACK
            /*success = WaitSegment(sd, ctx, ACK);
            if(success == false) {
                fprintf(stderr, "In control_loop: Waiting an ACK error\n");
                free(buffer);
                return;
            }*/
        }
        else if (event & NETWORK_DATA) {
            // receive data from the network layer
            data_len = stcp_network_recv(sd, (void *)buffer, max_len + sizeof(STCPHeader));
            if(data_len < sizeof(STCPHeader)) {
                fprintf(stderr, "In control_loop: Invalid Data from stcp_network_recv()\n");
                free(buffer);
                return;
            }
            STCPHeader *tcp_header = (STCPHeader *)buffer;

            // Closing Case
            if ((ctx->connection_state == CSTATE_ESTABLISHED) && (tcp_header->th_flags & TH_FIN)) {
                // 4-way handshake: Passive side
                // Current state: CLOSE_WAIT, sending ACK, send to app layer
                ctx->connection_state = CSTATE_CLOSE_WAIT;
                success = SendSegment(sd, ctx, ACK, NULL, 0);
                if(success == false) {
                    fprintf(stderr, "4-way handshake: sending an ACK error\n");
                    free(buffer);
                    return;
                }
                stcp_fin_received(sd);

                // Current state: LAST_ACK, sending FINACK, wait for an ACK
                ctx->connection_state = CSTATE_LAST_ACK;
                success = SendSegment(sd, ctx, FINACK, NULL, 0);
                if(success == false) {
                    fprintf(stderr, "4-way handshake: sending an FINACK error\n");
                    free(buffer);
                    return;
                }
                success = WaitSegment(sd, ctx, ACK);
                if(success == false) {
                    fprintf(stderr, "4-way handshake: waiting an ACK error\n");
                    free(buffer);
                    return;
                }

                // Current state: CLOSED, connection closed.
                ctx->connection_state = CSTATE_CLOSED;
                ctx->done = 1;
                break;
            }
            else if (data_len == sizeof(STCPHeader)) {
                // If receive an ACK
                // recovers the window
                ctx->remainder_window = (ctx->prev_len == 1) ? ctx->remainder_window : ctx->remainder_window + ntohl(tcp_header->th_ack) - ctx->rcvd_ack;
                ctx->rcvd_ack = ntohl(tcp_header->th_ack);
                ctx->rcvd_seq = ntohl(tcp_header->th_seq);
                ctx->rcvd_len = 1;
                //ctx->next_seq = ctx->rcvd_ack;
                //printf("After ACK: remain_window = %d\n", ctx->remainder_window);
            }
            // Network Data received.
            else {
                // Send Data to the application layer
                stcp_app_send(sd, ((char *)buffer + sizeof(STCPHeader)), (data_len - sizeof(STCPHeader)));

                // Update the context
                ctx->rcvd_ack = ntohl(tcp_header->th_ack);
                ctx->rcvd_seq = ntohl(tcp_header->th_seq);
                ctx->rcvd_len = data_len - sizeof(STCPHeader);

                // Send ACK
                success = SendSegment(sd, ctx, ACK, NULL, 0);
                if(success == false) {
                    fprintf(stderr, "In control_loop: sending an ACK error\n");
                    free(buffer);
                    return;
                }
            }
        }
        else if (event & APP_CLOSE_REQUESTED) {
            // 4-way handshake: Active side
            // Current state: ESTABLISHED, sending FINACK
            success = SendSegment(sd, ctx, FINACK, NULL, 0);
            if(success == false) {
                fprintf(stderr, "4-way handshake: sending a FINACK error\n");
                free(buffer);
                return;
            }

            // Current state: FIN_WAIT_1, waiting an ACK
            ctx->connection_state = CSTATE_FIN_WAIT_1;
            success = WaitSegment(sd, ctx, ACK);
            if(success == false) {
                fprintf(stderr, "4-way handshake: waiting an ACK error\n");
                free(buffer);
                return;
            }

            // Current state: FIN_WAIT_2, waiting a FINACK and then, sending an ACK
            ctx->connection_state = CSTATE_FIN_WAIT_2;
            success = WaitSegment(sd, ctx, FINACK);
            if(success == false) {
                fprintf(stderr, "4-way handshake: waiting a FINACK error\n");
                free(buffer);
                return;
            }
            success = SendSegment(sd, ctx, ACK, NULL, 0);
            if(success == false) {
                fprintf(stderr, "4-way handshake: sending an ACK error\n");
                free(buffer);
                return;
            }

            // Current state: CLOSED, connection closed.
            ctx->connection_state = CSTATE_CLOSED;
            ctx->done = 1;
            break;
        }
        else {
            fprintf(stderr, "In control_loop: Unexpected Event!\n");
            assert(0);
        }

        /* etc. */
    }
    free(buffer);
    return;
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

/**********************************************************************/
/* CreateSegment
 *
 * Create formatted segment and returns it.
 */
STCPHeader 
*CreateSegment(tcp_seq seq_no, tcp_seq ack_no, SegmentType type, char *data, size_t data_len) {
    STCPHeader *tcp_header = (STCPHeader *) malloc(sizeof(STCPHeader)+data_len);
    if(tcp_header == NULL) {
        assert(0);
    }
    // initialize header
    tcp_header->th_ack = htonl(ack_no);
    tcp_header->th_seq = htonl(seq_no);
    tcp_header->th_win = htons(WINDOW);
    tcp_header->th_off = 5;

    // Set Header Flag by Segment Type
    switch (type)
    {
    case SYN:
        tcp_header->th_flags = TH_SYN;
        break;
    case SYNACK:
        tcp_header->th_flags = TH_SYN | TH_ACK;
        break;
    case ACK:
        tcp_header->th_flags = TH_ACK;
        break;
    case DATA:
        // for the segment which has data
        assert(data && data_len);
        tcp_header->th_flags = TH_ACK;
        memcpy((void *)tcp_header + sizeof(STCPHeader), data, data_len);
        break;
    case FIN:
        tcp_header->th_flags = TH_FIN;
        break;
    case FINACK:
        tcp_header->th_flags = TH_FIN | TH_ACK;
        break;
    default:
        return NULL;
        break;
    }

    // return tcp header
    return tcp_header;
}

/**********************************************************************/
/* SendSegment
 *
 * Send segment and returns true if succeed.
 */
bool 
SendSegment(mysocket_t sd, context_t *ctx, SegmentType type, char *data, size_t data_len) {
    STCPHeader *segment;
    tcp_seq seq_no;
    tcp_seq ack_no;
    size_t byte;

    // Send Segment to Network Layer by Segment Type
    switch (type)
    {
    case SYN:
        ack_no = 0;
        seq_no = ctx->initial_sequence_num;
        ctx->prev_ack = ack_no;
        ctx->prev_seq = seq_no;
        ctx->prev_len = 1;
        break;
    case SYNACK:
        ack_no = ctx->rcvd_seq + 1;
        seq_no = ctx->initial_sequence_num;
        ctx->prev_ack = ack_no;
        ctx->prev_seq = seq_no;
        ctx->prev_len = 1;
        break;
    case ACK:
        ack_no = ctx->rcvd_seq + ctx->rcvd_len;
        seq_no = ctx->next_seq;
        ctx->prev_ack = ack_no;
        ctx->prev_seq = seq_no;
        ctx->prev_len = 1;
        break;
    case DATA:
        // for the segment which has data
        assert(data && data_len);
        ack_no = ctx->prev_ack;
        seq_no = ctx->next_seq;
        ctx->prev_ack = ack_no;
        ctx->prev_seq = seq_no;
        ctx->prev_len = data_len;
        ctx->remainder_window -= data_len;
        break;
    case FIN:
        ack_no = ctx->prev_ack;
        seq_no = ctx->next_seq;
        ctx->prev_ack = ack_no;
        ctx->prev_seq = seq_no;
        ctx->prev_len = 1;
        break;
    case FINACK:
        ack_no = ctx->prev_ack;
        seq_no = ctx->next_seq;
        ctx->prev_ack = ack_no;
        ctx->prev_seq = seq_no;
        ctx->prev_len = 1;
        break;
    default:
        return false;
        break;
    }
    
    // Create segment
    segment = CreateSegment(seq_no, ack_no, type, data, data_len);

    // Send
    byte = stcp_network_send(sd, segment, sizeof(STCPHeader) + data_len, NULL);
    // Free allocated memory.
    free(segment);
    // Success if return byte is positive.
    if(byte > 0/*sizeof(STCPHeader) + data_len*/) {
        return true;
    }

    // Should not reach here if succeed.
    return false;
}

/**********************************************************************/
/* WaitSegment
 *
 * Wait for the segment and returns true if succeed.
 * Do appropriate action for Segment Type.
 */
bool WaitSegment(mysocket_t sd, context_t *ctx, SegmentType type) {
    STCPHeader *segment = (STCPHeader *) malloc(sizeof(STCPHeader) + STCP_MSS);
    size_t byte;

    // Wait for the event
    stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    byte = stcp_network_recv(sd, (void *) segment, sizeof(STCPHeader) + STCP_MSS);

    // Check Validation
    if (byte < sizeof(STCPHeader)) {
        free(segment);
        return false;
    }

    // Do appropriate action by Seg. Type.
    // Firstly, Needs to check whether type is matched
    switch (type)
    {
    case SYN:
        if ((segment->th_flags & TH_SYN) == TH_SYN) {
            ctx->rcvd_ack = ntohl(segment->th_ack);
            ctx->rcvd_seq = ntohl(segment->th_seq);
            ctx->rcvd_len = (byte == sizeof(STCPHeader)) ? 1 : byte - sizeof(STCPHeader);
            ctx->next_seq = ctx->initial_sequence_num;
        }
        else {
            fprintf(stderr,"WaitSegment: SYN error\n");
            free(segment);
            return false;
        }
        break;
    case SYNACK:
        if (((segment->th_flags & TH_SYN) | (segment->th_flags & TH_ACK)) == (TH_SYN | TH_ACK)) {
            ctx->rcvd_ack = ntohl(segment->th_ack);
            ctx->rcvd_seq = ntohl(segment->th_seq);
            ctx->rcvd_len = (byte == sizeof(STCPHeader)) ? 1 : byte - sizeof(STCPHeader);
            ctx->next_seq = ctx->rcvd_ack;
        }
        else {
            fprintf(stderr,"WaitSegment: SYNACK error\n");
            free(segment);
            return false;
        }
        break;
    case ACK:
        if ((segment->th_flags & TH_ACK) == TH_ACK) {
            ctx->remainder_window = (ctx->prev_len == 1) ? ctx->remainder_window : ctx->remainder_window + ntohl(segment->th_ack) - ctx->rcvd_ack;
            ctx->rcvd_ack = ntohl(segment->th_ack);
            ctx->rcvd_seq = ntohl(segment->th_seq);
            ctx->rcvd_len = (byte == sizeof(STCPHeader)) ? 1 : byte - sizeof(STCPHeader);
            ctx->next_seq = ctx->rcvd_ack;
            //ctx->remainder_window = (ctx->prev_len == 1) ? ctx->remainder_window : ctx->remainder_window + ctx->prev_len;
        }
        else {
            fprintf(stderr,"WaitSegment: ACK error\n");
            free(segment);
            return false;
        }
        break;
    case FIN:
        if ((segment->th_flags & TH_FIN) == TH_FIN) {
            ctx->rcvd_ack = ntohl(segment->th_ack);
            ctx->rcvd_seq = ntohl(segment->th_seq);
            ctx->rcvd_len = (byte == sizeof(STCPHeader)) ? 1 : byte - sizeof(STCPHeader);
            ctx->next_seq = ctx->rcvd_ack;
        }
        else {
            fprintf(stderr,"WaitSegment: FIN error\n");
            free(segment);
            return false;
        }
        break;
    case FINACK:
        if (((segment->th_flags & TH_FIN) | (segment->th_flags & TH_ACK)) == (TH_FIN | TH_ACK)) {
            ctx->rcvd_ack = ntohl(segment->th_ack);
            ctx->rcvd_seq = ntohl(segment->th_seq);
            ctx->rcvd_len = (byte == sizeof(STCPHeader)) ? 1 : byte - sizeof(STCPHeader);
            ctx->next_seq = ctx->rcvd_ack;
        }
        else {
            fprintf(stderr,"WaitSegment: FINACK error\n");
            free(segment);
            return false;
        }
        break;
    default:
        fprintf(stderr,"WaitSegment: Invalid Segment Type!\n");
        free(segment);
        return false;
        break;
    }
    free(segment);
    return true;
}