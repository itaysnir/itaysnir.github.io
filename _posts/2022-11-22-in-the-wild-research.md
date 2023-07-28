---
layout: post
title:  "One Days - In-The-Wild Research"
date:   2022-11-22 19:59:43 +0300
categories: jekyll update
---

Contents
---
* TOC
{:toc}

## IDE Note

At this point I've started to use [Ecplise C / C++ package][eclipse] for code auditing. 

This IDE works pretty well under large scale of platforms (Linux, Windows, different archs and compilers, etc), similar to VScode (and unlike Clion). \
However, unlike VScode, it has even better static parsing mechanism, and faster navigation times. 

### Eclipse Config

By initializing Eclipse, select *Create C or C++ project* -> *Makefile Project*, and uncheck the *Generate Source and Makefile* option. 

Then, go to *Window* -> *Preferences* -> *Scalability*, and uncheck *Disable editor live parsing*, as well as *Alert me when scalability mode turned on* (which stops doing parsing for large files). \
Finally, change the scalability lines threshold to `999999` instead of `5000`.  

Next, type *Folding*, and select both *Enable folding of preprocessor branchs*, as well as *Enable folding of control flow statements*. 

Drag the project source folder into the workspace bar within the IDE (use *Link to Files and Folders* for projects involving many checkouts). 

After the indexing procedure has completed, right click on the project's properties. \
Navigate to *C / C++ Include Path* -> *Add Preprocessor Symbol*, and set interesting symbol values (may display different code paths, depending on `#ifdefs` for example). 

### Eclipse Tricks

1. Search: `ctrl + h`. \
It is suggested to disable `git search` via *customize*. 

File search - searches for *all* pattern matches within all files. \
C / C++ search - searches for particular elements we pick, for example functions definitions, symbols, structs, etc. 

2. To navigate between scopes, `alt + arrow`. 

3. Find all references: `ctrl + shift + g`. This is especially useful for variables. 

4. View all of the possible call paths involving a certain function: `ctrl + alt + h`. \
This is an *extremely* useful feature, as it can show us registration of function pointers, for example. \
This is a better alternative than the regular "find all references", and allows easy backtracing!

## CVE-2021-3434 - Zephyr RTOS

Im given a hint, that the attack surface is involved with Bluetooth's L2CAP packets. 
L2CAP is part of the Bluetooth stack, and serves as a "logical link control and adaptation" layer. 
It offers segmentation and reassembly for large packets, hence allows them to be transmited across BT links. 
It may receive packets of up to 64 kB, and breaks them to smaller MTU frames. The receiving end then reassembles these frames. 
The L2CAP layer negotiates about the optimal MTU negotiation with the other end. 

L2CAP frame format is very simple - length field (2 bytes) describing the packet data coming from the upper layers, channel ID (2 bytes), serves as an identifier for the virtual channel, and finally the underlying packet data (up to 64 kB). 

The frames as passed to the Host Controller Interface (HCI), sends them to the link manager (LM), which finally sends them to the link controller (transmits the frames within radio signals). 
Note that because this is a link-control protocol (ensuring packets are properly organized and routed to their destination), it is not suitable for audio transmission.



I've defined `CONFIG_BT_L2CAP_DYNAMIC_CHANNEL, CONFIG_BT_L2CAP_ECRED`, and searched for their occurences.
I've found an interesting file: `l2cap.c` and its header file, `l2cap.h`, both of them are around 3k loc.
Note there are two different versions - one for host, and another one denoted as shell. 

In order to learn the desired API of this kernel module, I've navigated through the header file. 
Most of it contains definitions about structs and interfaces the module uses. 
The exported API of this module is actually pretty simple, and consists of the following methods:
```c
int bt_l2cap_server_register(struct bt_l2cap_server *server);
int bt_l2cap_br_server_register(struct bt_l2cap_server *server);
int bt_l2cap_ecred_chan_connect(struct bt_conn *conn, struct bt_l2cap_chan **chans, int16_t psm);
int bt_l2cap_chan_connect(struct bt_conn *conn, struct bt_l2cap_chan *chan, uint16_t psm);
int bt_l2cap_chan_disconnect(struct bt_l2cap_chan *chan);
int bt_l2cap_chan_send(struct bt_l2cap_chan *chan, struct net_buf *buf);
int bt_l2cap_chan_recv_complete(struct bt_l2cap_chan *chan, struct net_buf *buf);
```
My initial though is to research surfaces where the user may control arbitrary data - hence I've focused on the receive method:
```c
int bt_l2cap_chan_recv_complete(struct bt_l2cap_chan *chan, struct net_buf *buf)
{
struct bt_l2cap_le_chan *ch = BT_L2CAP_LE_CHAN(chan);
struct bt_conn *conn = chan->conn;
uint16_t credits;
__ASSERT_NO_MSG(chan);
__ASSERT_NO_MSG(buf);

if (!conn) {
return -ENOTCONN;
}

if (conn->type != BT_CONN_TYPE_LE) {
return -ENOTSUP;
}

BT_DBG("chan %p buf %p", chan, buf);
/* Restore credits used by packet */
memcpy(&credits, net_buf_user_data(buf), sizeof(credits));
l2cap_chan_send_credits(ch, buf, credits);
net_buf_unref(buf);

return 0;
}
```
Indeed, we can see the L2CAP layer uses the credit mechanism as some sort of congestion control.
The user packet starts with 2 bytes of credit, denoting the amount of available bytes. 
This means a malicious packet may fully control the value of `credits`. 

The method `l2cap_chan_send_credits`:
```c
static void l2cap_chan_send_credits(struct bt_l2cap_le_chan *chan, struct net_buf *buf,  uint16_t credits)
{
struct bt_l2cap_le_credits *ev;
/* Cap the number of credits given */
if (credits > chan->rx.init_credits) {
credits = chan->rx.init_credits;
}

buf = l2cap_create_le_sig_pdu(buf, BT_L2CAP_LE_CREDITS, get_ident(),
sizeof(*ev));

if (!buf) {
BT_ERR("Unable to send credits update");
/* Disconnect would probably not work either so the only
* option left is to shutdown the channel.
*/
l2cap_chan_shutdown(&chan->chan);
return;
}

l2cap_chan_rx_give_credits(chan, credits);
ev = net_buf_add(buf, sizeof(*ev));
ev->cid = sys_cpu_to_le16(chan->rx.cid);
ev->credits = sys_cpu_to_le16(credits);
bt_l2cap_send(chan->chan.conn, BT_L2CAP_CID_LE_SIG, buf);
BT_DBG("chan %p credits %u", chan, atomic_get(&chan->rx.credits));
}
```
There is a simple sanity check for the value of `credits`. 
As we can see, it is compared against `chan->rx.init_credits`, which is also `uint16_t`, so this check is OK. 

Next, I've looked into `l2cap_recv`, which starts with the following definitions:
```c
static int l2cap_recv(struct bt_l2cap_chan *chan, struct net_buf *buf)
{
struct bt_l2cap *l2cap = CONTAINER_OF(chan, struct bt_l2cap, chan);
struct bt_l2cap_sig_hdr *hdr;
uint16_t len;

if (buf->len < sizeof(*hdr)) {
BT_ERR("Too small L2CAP signaling PDU");
return 0;
}

hdr = net_buf_pull_mem(buf, sizeof(*hdr));
len = sys_le16_to_cpu(hdr->len);
...
}
```
While `struct net_buf->len` is `uint16_t`, operator `sizeof()` actually returns a `uint32_t`. 
While comparing `uint16_t` to `uint32_t`, the first will be sign-extended to match the 32-bitness.



[eclipse]: https://www.eclipse.org/downloads/packages/release/2022-12/r/eclipse-ide-cc-developers
