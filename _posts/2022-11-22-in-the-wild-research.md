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

The research attack surface is said to be involved with Bluetooth's L2CAP packets. \
L2CAP is part of the Bluetooth stack, and serves as a "logical link control and adaptation" layer. \
It offers segmentation and reassembly for large packets, hence allows them to be transmited across BT links. \
It may receive packets of up to 64 kB, and breaks them to smaller MTU frames. The receiving end then reassembles these frames. \
The L2CAP layer negotiates about the optimal MTU negotiation with the other end. 

L2CAP frame format is very simple - length field (2 bytes) describing the packet data coming from the upper layers, channel ID (2 bytes), serves as an identifier for the virtual channel, and finally the underlying packet data (up to 64 kB).  

The frames as passed to the Host Controller Interface (HCI), sends them to the link manager (LM), which finally sends them to the link controller (transmits the frames within radio signals). \
Note that because this is a link-control protocol (ensuring packets are properly organized and routed to their destination), it is not suitable for audio transmission. 

I've defined `CONFIG_BT_L2CAP_DYNAMIC_CHANNEL, CONFIG_BT_L2CAP_ECRED`, and searched for their occurences. \
I've found an interesting file: `l2cap.c` and its header file, `l2cap.h`, both of them are around 3k loc. \
Note there are two different versions - one for host, and another one denoted as shell. 

In order to learn the desired API of this kernel module, I've navigated through the header file. \
Most of it contains definitions about structs and interfaces the module uses. \
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
Indeed, we can see the L2CAP layer uses the credit mechanism as some sort of congestion control. \
The user packet starts with 2 bytes of credit, denoting the amount of available bytes. \
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
There is a simple sanity check for the value of `credits`. \
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
While `struct net_buf->len` is `uint16_t`, operator `sizeof()` actually returns a `uint32_t`. \
While comparing `uint16_t` to `uint32_t`, the first will be sign-extended to match the 32-bitness, but since this is an unsigned comparision - this is OK.

Next, the call for `net_buf_pull_mem` triggers `net_buf_simple_pull_mem`. \
Notice how the internal buffer of `struct net_buf` is implemented:
```c
union {
/* The ABI of this struct must match net_buf_simple */
struct {
/** Pointer to the start of data in the buffer. */
uint8_t *data;
/** Length of the data behind the data pointer. */
uint16_t len;
/** Amount of data that this buffer can store. */
uint16_t size;
/** Start of the data storage. Not to be accessed
* directly (the data pointer should be used
* instead).
*/
uint8_t *__buf;
};
struct net_buf_simple b;
};
```
According to the comment, the `len` attribute actually counts the `"data behind the data pointer"`, meaning that it includes the two members `len` and `size`, hence contains the size of the underlying buffer, plus an extra 4 bytes. 

This means that in case the user sends an empty buffer, its length would be 4 bytes, and `hdr` would be initialized with 4 out-of-bounds bytes. \
Alternatively, it means we can pick arbitrary bytes for the received packet header (4 bytes). \
The packet's `hdr->code` may be used to trigger one handler of our wish. \
Three interesting of them:
```c
#if defined(CONFIG_BT_L2CAP_ECRED)
case BT_L2CAP_ECRED_CONN_REQ:
le_ecred_conn_req(l2cap, hdr->ident, buf);
break;

case BT_L2CAP_ECRED_CONN_RSP:
le_ecred_conn_rsp(l2cap, hdr->ident, buf);
break;

case BT_L2CAP_ECRED_RECONF_REQ:
le_ecred_reconf_req(l2cap, hdr->ident, buf);
break;
#endif /* defined(CONFIG_BT_L2CAP_ECRED) */```
Most of `le_ecred_reconf_req` doesn't seem to contain vulnerable code. \
However, while forging a response, it writes it to the buffer by simply calling `net_buf_add`:
```c
response:

buf = l2cap_create_le_sig_pdu(buf, BT_L2CAP_ECRED_RECONF_RSP, ident, sizeof(*rsp));
rsp = net_buf_add(buf, sizeof(*rsp));
rsp->result = sys_cpu_to_le16(result);
bt_l2cap_send(conn, BT_L2CAP_CID_LE_SIG, buf);
```
Internally, `net_buf_add` updates the `data` and `len` attributes, and performs a correct check involving the `size` attribute. 

### Vuln 0x01

Next, I've looked into `le_ecred_conn_req`, and found the following snippet interesting:
```c
uint16_t scid, dcid[L2CAP_ECRED_CHAN_MAX];
int i = 0;
...

while (buf->len >= sizeof(scid)) {
scid = net_buf_pull_le16(buf);
result = l2cap_chan_accept(conn, server, scid, mtu, mps,
credits, &chan[i]);

switch (result) {
case BT_L2CAP_LE_SUCCESS:
ch = BT_L2CAP_LE_CHAN(chan[i]);
dcid[i++] = sys_cpu_to_le16(ch->rx.cid);
continue;

/* Some connections refused – invalid Source CID */
case BT_L2CAP_LE_ERR_INVALID_SCID:
/* Some connections refused – Source CID already allocated */
case BT_L2CAP_LE_ERR_SCID_IN_USE:
/* If a Destination CID is 0x0000, the channel was not
* established.
*/
dcid[i++] = 0x0000;
continue;
	}
}
...
```
The array `dcid` is located on the stack, and contains 5 elements. \
Note how this array isn't initialized (which is another vuln).

However, the iteration variable `i` may grow without any limitation, depending on the amount of `scid` elements located within the inserted user buffer. \
This means that as long as we enter many `scid`s (may be the same one), we can override the stack with as many null-bytes as we wish!

### Vuln 0x02

Further reading this function, I've found another bug:
```c
response:

if (!i) {
i = buf->len / sizeof(scid);
}

buf = l2cap_create_le_sig_pdu(buf, BT_L2CAP_ECRED_CONN_RSP, ident, 
							  sizeof(*rsp) + (sizeof(scid) * i));
rsp = net_buf_add(buf, sizeof(*rsp));
(void)memset(rsp, 0, sizeof(*rsp));

if (result == BT_L2CAP_LE_ERR_UNACCEPT_PARAMS ||
result == BT_L2CAP_LE_ERR_PSM_NOT_SUPP ||
result == BT_L2CAP_LE_ERR_AUTHENTICATION) {
memset(dcid, 0, sizeof(scid) * i);
} 
else if (ch) {
rsp->mps = sys_cpu_to_le16(ch->rx.mps);
rsp->mtu = sys_cpu_to_le16(ch->rx.mtu);
rsp->credits = sys_cpu_to_le16(ch->rx.init_credits);
}

net_buf_add_mem(buf, dcid, sizeof(scid) * i);
```
We can see `l2cap_create_le_sig_pdu` is called, in order to forge an header consisting enough space for the response, and `i` amount of `scid`s.

However, since the user input may fully control the amount of `scid`s, `sizeof(*rsp) + (sizeof(scid) * i)` may grow without bounds, potentially triggering an integer overflow. \
This means the `len` attribute of the created response header will contain some very small value. \
That way, we may for example force the assertion of `net_buff_add` to fail, and crash the program. 

### Vuln 0x03

The call for `net_buf_add_mem(buf, dcid, sizeof(scid) * i)` - as we fully control the value of `i`, and `dcid` is statically allocated on the stack. \
It means we can leak stack content into the sent response buffer. 


## CVE-2021-25217 -  ISC DHCP

The attack surface is said to be involved with parsing of lease files. \
According to `man 5 dhcpd.leases`, a DHCP server saves a persistent DB (= on disk) of leases that it has assigned. \
This DB file is ASCII file, containing series of lease declarations. \
For every lease change, its new value is recorded at the end of the lease file - meaning the current value is the last written declaration. 

Usually, the leases DB file is stored within `/var/lib/dhcpd/dhcpd.leases`. \
In order to prevent this file from exploading, the file is rewritten from time to time - by creating a temporary lease file, renaming the old file as `/var/lib/dhcpd/dhcpd.leases~`. 

A good starting point is found by searching for `"dhcpd.leases"` string:
```c
isc_result_t read_conf_file (const char *filename, struct group *group,
			     int group_type, int leasep)
{
	int file;
	struct parse *cfile;
	isc_result_t status;

	if ((file = open (filename, O_RDONLY)) < 0) {
		if (leasep) {
			log_error ("Can't open lease database %s: %m --",
				   path_dhcpd_db);
			log_error ("  check for failed database %s!",
				   "rewrite attempt");
			log_error ("Please read the dhcpd.leases manual%s",
				   " page if you");
			log_fatal ("don't know what to do about this.");
		} else {
			log_fatal ("Can't open %s: %m", filename);
		}
	}
	...
}
```

Then, in case the `leasep` flag is True, it initializes a `struct parse *cfile` via `new_parse`, and calls `lease_file_subparse`, which seems interesting:
```c
isc_result_t lease_file_subparse (struct parse *cfile)
{
	const char *val;
	enum dhcp_token token;
	isc_result_t status;

	do {
		token = next_token (&val, (unsigned *)0, cfile);
		if (token == END_OF_FILE)
			break;
		if (token == LEASE) {
			struct lease *lease = (struct lease *)0;
			if (parse_lease_declaration (&lease, cfile)) {
				enter_lease (lease);
				lease_dereference (&lease, MDL);
			} else
				parse_warn (cfile,
					    "possibly corrupt lease file");
		} else if (token == IA_NA) {
			parse_ia_na_declaration(cfile);
		} else if (token == IA_TA) {
			parse_ia_ta_declaration(cfile);
		} else if (token == IA_PD) {
			parse_ia_pd_declaration(cfile);
		} else if (token == CLASS) {
			parse_class_declaration(0, cfile, root_group,
						CLASS_TYPE_CLASS);
		} else if (token == SUBCLASS) {
			parse_class_declaration(0, cfile, root_group,
						CLASS_TYPE_SUBCLASS);
		} else if (token == HOST) {
			parse_host_declaration (cfile, root_group);
		} else if (token == GROUP) {
			parse_group_declaration (cfile, root_group);
		...
		} else if (token == AUTHORING_BYTE_ORDER) {
			parse_authoring_byte_order(cfile);
		} else {
			log_error ("Corrupt lease file - possible data loss!");
			skip_to_semi (cfile);
		}

	} while (1);

	status = cfile->warnings_occurred ? DHCP_R_BADPARSE : ISC_R_SUCCESS;
	return status;
}
```
This function reads the lease file, token after token. 

Most of the methods are irrelevant, as they require DHCPv6. \
This leaves us with:
```c
parse_lease_declaration()
enter_lease()
lease_dereference()
parse_class_declaration()
parse_host_declaration()
parse_group_declaration()
```
`parse_host_declaration` internally calls `parse_host_name`. \
This method assembles multiple strings, splitted by dot, into a single allocated string, representing the hostname. 
```c
do {
/* Read a token, which should be an identifier. */
token = peek_token (&val, (unsigned *)0, cfile);
if (!is_identifier (token) && token != NUMBER)
break;
skip_token(&val, (unsigned *)0, cfile);
/* Store this identifier... */
if (!(s = (char *)dmalloc (strlen (val) + 1, MDL)))
log_fatal ("can't allocate temp space for hostname.");
strcpy (s, val);
c = cons ((caddr_t)s, c);
len += strlen (s) + 1;
/* Look for a dot; if it's there, keep going, otherwise
we're done. */
token = peek_token (&val, (unsigned *)0, cfile);
if (token == DOT) {
token = next_token (&val, (unsigned *)0, cfile);
ltid = 1;
} else
ltid = 0;
} while (token == DOT);
```
Note how the `len` variable may grow without limitation. \
However, in order to exploit this integer overflow, a file of length 4GB would be needed. 

I've taken a deeper look into the following methods, as hinted by looking into semicolon parsing:
```c
parse_ip6_addr
parse_cshl
parse_X
```
###  Vuln
The function `parse_X` is being called from multiple sites, most of them sending it a local stack buffer, and its size:
```c
/* Consider merging parse_cshl into this. */

int parse_X (cfile, buf, max)
struct parse *cfile;
u_int8_t *buf;
unsigned max;
{
int token;
const char *val;
unsigned len;
token = peek_token (&val, (unsigned *)0, cfile);
if (token == NUMBER_OR_NAME || token == NUMBER) {
len = 0;

do {
token = next_token (&val, (unsigned *)0, cfile);
if (token != NUMBER && token != NUMBER_OR_NAME) {
parse_warn (cfile,
"expecting hexadecimal constant.");
skip_to_semi (cfile);
return 0;

}
convert_num (cfile, &buf [len], val, 16, 8);

if (len++ > max) {
parse_warn (cfile,
"hexadecimal constant too long.");
skip_to_semi (cfile);
return 0;

}
token = peek_token (&val, (unsigned *)0, cfile);

if (token == COLON)
token = next_token (&val,
(unsigned *)0, cfile);

} while (token == COLON);

val = (char *)buf;
}

return len;
}
```

In case of inserting multiple colons, `convert_num` would be called multiple times. \
While there is a sanity check `if(len++ > max)`, it isn't sufficient for two reasons:

1. It is actually performed after `convert_num` is being issued, classic off-by-one scenario
2. In case `max == 128`, the last possible index to access should be 127. 
   However, the check is being performed for `max` , instead of `max - 1`. 
   Moreover, note this is a `right++` operator, meaning the increment would occur only after the check was being performed.
   
These findings yields the fact that there is a possible off-by-two stack vulnerability here, as `128++ > 128` would be evaluated to false, yielding another iteration.

The methods `parse_cshl` and `parse_ip6_addr` didn't contain any vuln. 




[eclipse]: https://www.eclipse.org/downloads/packages/release/2022-12/r/eclipse-ide-cc-developers
